#!/usr/bin/env python3
"""
deliverability_cli.py — Zero-dependency Python 3.9+ CLI with a native RFC 1035 DNS client
to audit domain MX, SPF (10-lookup RFC 7208 limit), DMARC, and DKIM deliverability hygiene.
"""

from __future__ import annotations

import argparse
import base64
import csv
from dataclasses import asdict, dataclass, field
import io
import json
from pathlib import Path
import random
import re
import socket
import struct
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Set, Tuple, Union


__version__ = "1.0.0"

# RFC 1035 DNS constants
QTYPE_IDS: Dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
ID_TO_QTYPE: Dict[int, str] = {v: k for k, v in QTYPE_IDS.items()}
QCLASS_IN = 1

RCODE_NAMES: Dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

DEFAULT_DNS_SERVERS = ("1.1.1.1", "8.8.8.8")
DEFAULT_DKIM_SELECTORS = (
    "google",
    "selector1",
    "selector2",
    "default",
    "dkim",
    "k1",
    "s1",
    "s2",
    "mail",
)

MAX_SPF_DNS_LOOKUPS = 10
MAX_CNAME_DEPTH = 6
MAX_SPF_RECURSION_DEPTH = 15

_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
_SELECTOR_RE = re.compile(r"^[a-zA-Z0-9_-]{1,63}(?:\.[a-zA-Z0-9_-]{1,63})*$")


class DnsError(Exception):
    """Base error for DNS client operations."""


class DnsProtocolError(DnsError):
    """Raised on malformed RFC 1035 packets or compression pointer loops."""


class DnsTimeoutError(DnsError):
    """Raised when UDP/TCP DNS queries time out."""


@dataclass(frozen=True)
class MxValue:
    """Parsed MX resource record value."""

    preference: int
    exchange: str


@dataclass(frozen=True)
class DnsRecord:
    """Normalized DNS resource record."""

    name: str
    qtype: str
    ttl: int
    value: Any  # str for TXT/CNAME/A/AAAA/PTR/NS, MxValue for MX


@dataclass
class DnsQueryResult:
    """Result returned by a DNS resolver for a single (name, qtype) lookup."""

    name: str
    qtype: str
    rcode: int = 0
    records: List[DnsRecord] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, f"RCODE_{self.rcode}")


class DnsResolver(Protocol):
    """Protocol for injectable DNS resolvers (native UDP/TCP or offline mock)."""

    def query(self, name: str, qtype: str) -> DnsQueryResult:
        ...


def normalize_domain(raw: str) -> str:
    """Normalize a domain, URL, or email string into a bare lowercase domain name."""
    value = raw.strip()
    if not value:
        raise ValueError("Domain cannot be empty.")

    # Strip scheme if a URL was supplied
    if "://" in value:
        value = value.split("://", 1)[1]
        value = value.split("/", 1)[0]
    # Strip email local-part if an email address was supplied
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    # Strip port if supplied
    if ":" in value and not value.startswith("["):
        value = value.split(":", 1)[0]

    value = value.strip().rstrip(".").lower()
    if not value:
        raise ValueError(f"Invalid domain: {raw!r}")

    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid IDNA domain {raw!r}: {exc}") from exc

    if len(ascii_domain) > 253:
        raise ValueError(f"Domain exceeds 253 characters: {raw!r}")

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        raise ValueError(f"Domain must contain at least one dot: {raw!r}")
    for label in labels:
        # Allow underscore prefix for service/DKIM/DMARC domain names (_dmarc, _domainkey)
        clean_label = label.lstrip("_") if label.startswith("_") else label
        if not clean_label or not _DOMAIN_LABEL_RE.match(clean_label):
            if label != "*":
                raise ValueError(f"Invalid DNS label {label!r} in domain {raw!r}")
    return ascii_domain


def encode_dns_name(name: str) -> bytes:
    """Encode a domain name into RFC 1035 wire-format label sequence."""
    clean = name.strip().rstrip(".")
    if not clean:
        return b"\x00"
    ascii_name = clean.encode("idna").decode("ascii")
    if len(ascii_name) > 253:
        raise DnsProtocolError(f"DNS name exceeds 253 bytes: {name!r}")
    out = bytearray()
    for label in ascii_name.split("."):
        encoded = label.encode("ascii")
        if not (1 <= len(encoded) <= 63):
            raise DnsProtocolError(f"Invalid DNS label length for {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def decode_dns_name(packet: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode an RFC 1035 domain name from `packet` starting at `offset`,
    handling Section 4.1.4 message compression pointers (0xC0xx) with loop detection.
    Returns `(domain_name, next_offset_after_name_field)`.
    """
    labels: List[str] = []
    visited_pointers: Set[int] = set()
    jumped = False
    next_offset = offset
    packet_len = len(packet)
    steps = 0

    while True:
        if offset >= packet_len:
            raise DnsProtocolError("Unexpected end of DNS packet while decoding name.")
        steps += 1
        if steps > 128:
            raise DnsProtocolError("Excessive label steps while decoding DNS name.")

        length = packet[offset]
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break

        tag = length & 0xC0
        if tag == 0xC0:
            if offset + 1 >= packet_len:
                raise DnsProtocolError("Truncated DNS compression pointer.")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer >= packet_len:
                raise DnsProtocolError(f"DNS compression pointer out of range: {pointer}")
            if pointer in visited_pointers:
                raise DnsProtocolError("DNS compression pointer loop detected.")
            visited_pointers.add(pointer)
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        if tag != 0:
            raise DnsProtocolError(f"Invalid DNS label length prefix bits: 0x{length:02x}")

        offset += 1
        if offset + length > packet_len:
            raise DnsProtocolError("Truncated DNS label payload.")
        label_bytes = packet[offset : offset + length]
        labels.append(label_bytes.decode("utf-8", errors="replace"))
        offset += length

    return ".".join(labels), next_offset


def build_dns_query(
    qname: str,
    qtype: str,
    tx_id: Optional[int] = None,
    recursion_desired: bool = True,
) -> Tuple[int, bytes]:
    """Build a raw RFC 1035 DNS query packet for `(qname, qtype)`."""
    qtype_upper = qtype.upper()
    if qtype_upper not in QTYPE_IDS:
        raise ValueError(f"Unsupported DNS query type: {qtype!r}")
    qid = random.randint(0, 0xFFFF) if tx_id is None else (tx_id & 0xFFFF)
    flags = 0x0100 if recursion_desired else 0x0000
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    question = encode_dns_name(qname) + struct.pack("!HH", QTYPE_IDS[qtype_upper], QCLASS_IN)
    return qid, header + question


def _parse_txt_rdata(rdata: bytes) -> str:
    """Concatenate RFC 1035 <character-string> segments inside a TXT RDATA payload."""
    parts: List[str] = []
    pos = 0
    total = len(rdata)
    while pos < total:
        seg_len = rdata[pos]
        pos += 1
        if pos + seg_len > total:
            raise DnsProtocolError("Truncated TXT character-string segment.")
        parts.append(rdata[pos : pos + seg_len].decode("utf-8", errors="replace"))
        pos += seg_len
    return "".join(parts)


def parse_dns_response(
    packet: bytes,
    expected_tx_id: Optional[int] = None,
) -> Tuple[int, bool, List[DnsRecord]]:
    """
    Parse a raw RFC 1035 DNS response packet.
    Returns `(rcode, truncated_flag, answer_records)`.
    """
    if len(packet) < 12:
        raise DnsProtocolError(f"DNS response shorter than 12-byte header ({len(packet)} bytes).")

    tx_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", packet[:12])
    if expected_tx_id is not None and tx_id != (expected_tx_id & 0xFFFF):
        raise DnsProtocolError(
            f"DNS transaction ID mismatch: expected 0x{expected_tx_id:04x}, got 0x{tx_id:04x}"
        )

    qr = (flags >> 15) & 1
    if qr != 1:
        raise DnsProtocolError("DNS packet QR bit is 0 (expected response, got query).")

    truncated = bool((flags >> 9) & 1)
    rcode = flags & 0x0F

    offset = 12
    for _ in range(qdcount):
        _qname, offset = decode_dns_name(packet, offset)
        if offset + 4 > len(packet):
            raise DnsProtocolError("Truncated DNS question section.")
        offset += 4

    records: List[DnsRecord] = []
    for _ in range(ancount):
        rr_name, offset = decode_dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise DnsProtocolError("Truncated DNS resource record header.")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        rdata_offset = offset
        if rdata_offset + rdlength > len(packet):
            raise DnsProtocolError("Truncated DNS resource record RDATA.")
        rdata = packet[rdata_offset : rdata_offset + rdlength]
        offset = rdata_offset + rdlength

        if rclass != QCLASS_IN:
            continue

        qtype_name = ID_TO_QTYPE.get(rtype, f"TYPE{rtype}")
        parsed_value: Any

        if rtype == QTYPE_IDS["TXT"]:
            parsed_value = _parse_txt_rdata(rdata)
        elif rtype == QTYPE_IDS["MX"]:
            if rdlength < 3:
                raise DnsProtocolError("Truncated MX RDATA.")
            pref = struct.unpack("!H", rdata[:2])[0]
            exchange, _ = decode_dns_name(packet, rdata_offset + 2)
            parsed_value = MxValue(preference=pref, exchange=exchange.lower())
        elif rtype in (QTYPE_IDS["CNAME"], QTYPE_IDS["PTR"], QTYPE_IDS["NS"]):
            target, _ = decode_dns_name(packet, rdata_offset)
            parsed_value = target.lower()
        elif rtype == QTYPE_IDS["A"] and rdlength == 4:
            parsed_value = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == QTYPE_IDS["AAAA"] and rdlength == 16:
            parsed_value = socket.inet_ntop(socket.AF_INET6, rdata)
        else:
            parsed_value = rdata.hex()

        records.append(
            DnsRecord(
                name=rr_name.lower(),
                qtype=qtype_name,
                ttl=ttl,
                value=parsed_value,
            )
        )

    return rcode, truncated, records


class NativeDnsClient:
    """
    Native pure-stdlib RFC 1035 UDP DNS client with automatic TCP fallback on TC=1
    and CNAME resolution support.
    """

    def __init__(
        self,
        servers: Sequence[str] = DEFAULT_DNS_SERVERS,
        port: int = 53,
        timeout: float = 3.0,
        retries: int = 1,
        tcp_fallback: bool = True,
    ) -> None:
        if not servers:
            raise ValueError("At least one DNS server IP must be configured.")
        self.servers = list(servers)
        self.port = port
        self.timeout = timeout
        self.retries = max(0, retries)
        self.tcp_fallback = tcp_fallback

    def _send_udp(self, server: str, packet: bytes, tx_id: int) -> Tuple[int, bool, List[DnsRecord]]:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(packet, (server, self.port))
            while True:
                data, _addr = sock.recvfrom(4096)
                if len(data) >= 2 and struct.unpack("!H", data[:2])[0] != (tx_id & 0xFFFF):
                    continue
                return parse_dns_response(data, expected_tx_id=tx_id)

    def _send_tcp(self, server: str, packet: bytes, tx_id: int) -> Tuple[int, bool, List[DnsRecord]]:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        framed = struct.pack("!H", len(packet)) + packet
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect((server, self.port))
            sock.sendall(framed)
            length_bytes = self._recv_exact(sock, 2)
            resp_len = struct.unpack("!H", length_bytes)[0]
            payload = self._recv_exact(sock, resp_len)
            return parse_dns_response(payload, expected_tx_id=tx_id)

    @staticmethod
    def _recv_exact(sock: socket.socket, count: int) -> bytes:
        chunks: List[bytes] = []
        remaining = count
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise DnsProtocolError("Unexpected EOF during TCP DNS response.")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _query_raw(self, qname: str, qtype: str) -> DnsQueryResult:
        qtype_upper = qtype.upper()
        last_error: Optional[str] = None

        for _attempt in range(self.retries + 1):
            for server in self.servers:
                tx_id, packet = build_dns_query(qname, qtype_upper)
                try:
                    rcode, truncated, records = self._send_udp(server, packet, tx_id)
                    if truncated and self.tcp_fallback:
                        rcode, _trunc_tcp, records = self._send_tcp(server, packet, tx_id)
                    return DnsQueryResult(
                        name=qname.lower(),
                        qtype=qtype_upper,
                        rcode=rcode,
                        records=records,
                    )
                except socket.timeout:
                    last_error = f"DNS query timed out ({server}:{self.port}) for {qname} {qtype_upper}"
                except OSError as exc:
                    last_error = f"DNS network error ({server}:{self.port}): {exc}"
                except DnsProtocolError as exc:
                    last_error = f"DNS protocol error ({server}:{self.port}): {exc}"

        return DnsQueryResult(
            name=qname.lower(),
            qtype=qtype_upper,
            rcode=2,
            records=[],
            error=last_error or "DNS query failed",
        )

    def query(self, name: str, qtype: str) -> DnsQueryResult:
        """Query `(name, qtype)` following CNAME chains when target records are aliases."""
        target = name.strip().rstrip(".").lower()
        qtype_upper = qtype.upper()
        cnames: List[str] = []
        seen: Set[str] = {target}

        for _ in range(MAX_CNAME_DEPTH):
            res = self._query_raw(target, qtype_upper)
            if res.error:
                res.cnames = cnames
                return res

            direct = [r for r in res.records if r.qtype == qtype_upper]
            if direct or qtype_upper == "CNAME":
                res.records = direct if qtype_upper != "CNAME" else res.records
                res.cnames = cnames
                return res

            cname_records = [r for r in res.records if r.qtype == "CNAME" and isinstance(r.value, str)]
            if not cname_records:
                res.cnames = cnames
                return res

            next_target = cname_records[0].value.strip().rstrip(".").lower()
            cnames.append(next_target)
            if next_target in seen:
                res.error = f"CNAME loop detected at {next_target}"
                res.cnames = cnames
                return res
            seen.add(next_target)
            target = next_target

        return DnsQueryResult(
            name=name.strip().rstrip(".").lower(),
            qtype=qtype_upper,
            rcode=2,
            records=[],
            cnames=cnames,
            error=f"Exceeded maximum CNAME depth ({MAX_CNAME_DEPTH})",
        )


class MockDnsResolver:
    """
    Offline deterministic DNS resolver for unit testing and sandboxed simulations.

    `zone` maps `(domain_lower, qtype_upper)` -> list of values:
      - TXT: `str`
      - MX: `(preference, exchange)` or `MxValue(preference, exchange)`
      - CNAME/A/AAAA/NS/PTR: `str`
      - Or `DnsRecord`, `DnsQueryResult`, or an `Exception` instance to simulate errors.
    """

    def __init__(
        self,
        zone: Optional[Dict[Tuple[str, str], Any]] = None,
        nxdomains: Optional[Iterable[str]] = None,
    ) -> None:
        self.zone: Dict[Tuple[str, str], Any] = {}
        if zone:
            for (name, qtype), val in zone.items():
                self.zone[(name.strip().rstrip(".").lower(), qtype.upper())] = val
        self.nxdomains: Set[str] = {d.strip().rstrip(".").lower() for d in (nxdomains or ())}
        self.query_log: List[Tuple[str, str]] = []

    def add(self, name: str, qtype: str, values: Any) -> None:
        self.zone[(name.strip().rstrip(".").lower(), qtype.upper())] = values

    def _to_records(self, name: str, qtype: str, raw_items: Sequence[Any]) -> List[DnsRecord]:
        out: List[DnsRecord] = []
        for item in raw_items:
            if isinstance(item, DnsRecord):
                out.append(item)
            elif qtype == "MX":
                if isinstance(item, MxValue):
                    out.append(DnsRecord(name=name, qtype="MX", ttl=300, value=item))
                elif isinstance(item, tuple) and len(item) == 2:
                    out.append(
                        DnsRecord(
                            name=name,
                            qtype="MX",
                            ttl=300,
                            value=MxValue(preference=int(item[0]), exchange=str(item[1]).rstrip(".").lower()),
                        )
                    )
                else:
                    raise TypeError(f"Unsupported MX mock record: {item!r}")
            else:
                val = str(item)
                if qtype in ("CNAME", "NS", "PTR"):
                    val = val.strip().rstrip(".").lower()
                out.append(DnsRecord(name=name, qtype=qtype, ttl=300, value=val))
        return out

    def query(self, name: str, qtype: str) -> DnsQueryResult:
        qname = name.strip().rstrip(".").lower()
        qtype_upper = qtype.upper()
        self.query_log.append((qname, qtype_upper))

        target = qname
        cnames: List[str] = []
        seen: Set[str] = {target}

        for _ in range(MAX_CNAME_DEPTH):
            if target in self.nxdomains:
                return DnsQueryResult(name=qname, qtype=qtype_upper, rcode=3, cnames=cnames)

            entry = self.zone.get((target, qtype_upper))
            if isinstance(entry, Exception):
                return DnsQueryResult(
                    name=qname,
                    qtype=qtype_upper,
                    rcode=2,
                    cnames=cnames,
                    error=str(entry),
                )
            if isinstance(entry, DnsQueryResult):
                return DnsQueryResult(
                    name=qname,
                    qtype=qtype_upper,
                    rcode=entry.rcode,
                    records=list(entry.records),
                    cnames=cnames + list(entry.cnames),
                    error=entry.error,
                )

            if entry is not None:
                raw_list = list(entry) if isinstance(entry, (list, tuple)) and not (
                    qtype_upper == "MX" and len(entry) == 2 and isinstance(entry[0], int)
                ) else [entry]
                records = self._to_records(target, qtype_upper, raw_list)
                return DnsQueryResult(
                    name=qname,
                    qtype=qtype_upper,
                    rcode=0,
                    records=records,
                    cnames=cnames,
                )

            # Check explicit CNAME alias if direct record wasn't defined
            if qtype_upper != "CNAME":
                cname_entry = self.zone.get((target, "CNAME"))
                if cname_entry:
                    cname_vals = list(cname_entry) if isinstance(cname_entry, (list, tuple)) else [cname_entry]
                    next_target = str(cname_vals[0]).strip().rstrip(".").lower()
                    cnames.append(next_target)
                    if next_target in seen:
                        return DnsQueryResult(
                            name=qname,
                            qtype=qtype_upper,
                            rcode=2,
                            cnames=cnames,
                            error=f"CNAME loop detected at {next_target}",
                        )
                    seen.add(next_target)
                    target = next_target
                    continue

            return DnsQueryResult(name=qname, qtype=qtype_upper, rcode=0, records=[], cnames=cnames)

        return DnsQueryResult(
            name=qname,
            qtype=qtype_upper,
            rcode=2,
            cnames=cnames,
            error=f"Exceeded maximum CNAME depth ({MAX_CNAME_DEPTH})",
        )


# ---------------------------------------------------------------------------
# Audit Data Models
# ---------------------------------------------------------------------------


@dataclass
class AuditIssue:
    severity: str  # ERROR, WARN, INFO
    category: str  # MX, SPF, DMARC, DKIM
    code: str
    message: str


@dataclass
class FixRecord:
    category: str
    host: str
    record_type: str
    ttl: int
    value: str
    reason: str
    priority: Optional[int] = None

    def format_zone_line(self) -> str:
        if self.record_type == "MX" and self.priority is not None:
            return f"{self.host}  {self.ttl}  IN  MX  {self.priority} {self.value}"
        if self.record_type == "TXT":
            escaped = self.value.replace('"', '\\"')
            return f'{self.host}  {self.ttl}  IN  TXT  "{escaped}"'
        return f"{self.host}  {self.ttl}  IN  {self.record_type}  {self.value}"


@dataclass
class SpfLookupStep:
    domain: str
    mechanism: str
    lookups_added: int
    depth: int
    note: str = ""


@dataclass
class SpfAudit:
    status: str  # PASS, WARN, FAIL, MISSING
    records_found: List[str] = field(default_factory=list)
    duplicate_records: bool = False
    lookup_count: int = 0
    lookup_limit: int = MAX_SPF_DNS_LOOKUPS
    exceeds_lookup_limit: bool = False
    all_qualifier: Optional[str] = None  # "-", "~", "?", "+", or None
    has_redirect: bool = False
    circular_include: bool = False
    broken_includes: List[str] = field(default_factory=list)
    uses_ptr: bool = False
    lookup_steps: List[SpfLookupStep] = field(default_factory=list)
    score: int = 0
    max_score: int = 30


@dataclass
class MxAudit:
    status: str  # PASS, WARN, FAIL, MISSING
    records: List[MxValue] = field(default_factory=list)
    null_mx: bool = False
    score: int = 0
    max_score: int = 20


@dataclass
class DmarcAudit:
    status: str  # PASS, WARN, FAIL, MISSING
    records_found: List[str] = field(default_factory=list)
    duplicate_records: bool = False
    policy: Optional[str] = None  # reject, quarantine, none
    subdomain_policy: Optional[str] = None
    pct: int = 100
    rua: List[str] = field(default_factory=list)
    ruf: List[str] = field(default_factory=list)
    adkim: str = "r"
    aspf: str = "r"
    score: int = 0
    max_score: int = 30


@dataclass
class DkimSelectorResult:
    selector: str
    fqdn: str
    found: bool
    status: str  # ACTIVE, REVOKED, TESTING, MISSING, INVALID
    record: Optional[str] = None
    key_type: Optional[str] = None
    key_bits: Optional[int] = None
    cnames: List[str] = field(default_factory=list)


@dataclass
class DkimAudit:
    status: str  # PASS, WARN, FAIL, MISSING
    selectors_probed: List[str] = field(default_factory=list)
    selectors_found: List[DkimSelectorResult] = field(default_factory=list)
    score: int = 0
    max_score: int = 20


@dataclass
class DomainAuditResult:
    domain: str
    score: int
    grade: str
    mx: MxAudit
    spf: SpfAudit
    dmarc: DmarcAudit
    dkim: DkimAudit
    issues: List[AuditIssue] = field(default_factory=list)
    fixes: List[FixRecord] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Audit Logic
# ---------------------------------------------------------------------------


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    if score >= 25:
        return "D"
    return "F"


def _audit_mx(domain: str, resolver: DnsResolver) -> Tuple[MxAudit, List[AuditIssue], List[FixRecord]]:
    issues: List[AuditIssue] = []
    fixes: List[FixRecord] = []

    res = resolver.query(domain, "MX")
    if res.error:
        issues.append(
            AuditIssue("ERROR", "MX", "MX_DNS_ERROR", f"Failed to query MX records: {res.error}")
        )
        return MxAudit(status="FAIL", score=0), issues, fixes

    mx_vals: List[MxValue] = []
    for rec in res.records:
        if rec.qtype == "MX" and isinstance(rec.value, MxValue):
            mx_vals.append(rec.value)

    mx_vals.sort(key=lambda m: (m.preference, m.exchange))

    if not mx_vals:
        issues.append(
            AuditIssue(
                "ERROR",
                "MX",
                "MX_MISSING",
                f"No MX records found for {domain}. Domain cannot reliably receive inbound email.",
            )
        )
        fixes.append(
            FixRecord(
                category="MX",
                host=f"{domain}.",
                record_type="MX",
                ttl=3600,
                priority=10,
                value=f"mail.{domain}.",
                reason="Add primary MX record (replace mail host with your email provider MX).",
            )
        )
        return MxAudit(status="MISSING", records=[], score=0), issues, fixes

    # Check RFC 7505 Null MX (0 .)
    if any(m.preference == 0 and m.exchange in ("", ".") for m in mx_vals):
        issues.append(
            AuditIssue(
                "WARN",
                "MX",
                "MX_NULL_RECORD",
                f"Domain {domain} publishes an RFC 7505 Null MX ('0 .') rejecting all inbound mail.",
            )
        )
        return MxAudit(status="WARN", records=mx_vals, null_mx=True, score=0), issues, fixes

    # Check for bare IP literals in MX exchange (RFC 5321 violation)
    invalid_targets = [
        m.exchange
        for m in mx_vals
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", m.exchange) or m.exchange in ("", "localhost")
    ]
    if invalid_targets:
        issues.append(
            AuditIssue(
                "WARN",
                "MX",
                "MX_INVALID_TARGET",
                f"MX exchange target(s) must be valid hostnames, not IPs/localhost: {', '.join(invalid_targets)}",
            )
        )
        return MxAudit(status="WARN", records=mx_vals, score=12), issues, fixes

    return MxAudit(status="PASS", records=mx_vals, score=20), issues, fixes


def _is_spf_record(txt: str) -> bool:
    stripped = txt.strip().lower()
    return stripped == "v=spf1" or stripped.startswith("v=spf1 ") or stripped.startswith("v=spf1\t")


def _extract_spf_qualifier_and_term(token: str) -> Tuple[str, str]:
    if token and token[0] in ("+", "-", "~", "?"):
        return token[0], token[1:]
    return "+", token


def _merge_spf_records(records: Sequence[str]) -> str:
    """Create a deduplicated merged SPF record from duplicate `v=spf1` records."""
    mechanisms: List[str] = []
    seen_lower: Set[str] = set()
    final_all = "-all"

    for rec in records:
        tokens = rec.strip().split()
        for tok in tokens[1:]:
            q, body = _extract_spf_qualifier_and_term(tok)
            body_l = body.lower()
            if body_l == "all":
                # Keep strictest qualifier encountered (prefer -all, else ~all)
                if q == "-" or final_all not in ("-all",):
                    final_all = "-all" if q == "-" else ("~all" if q == "~" else final_all)
                continue
            if body_l.startswith("redirect=") or body_l.startswith("exp="):
                continue
            canonical = tok if tok[0] in ("+", "-", "~", "?") else body
            if canonical.lower() not in seen_lower:
                seen_lower.add(canonical.lower())
                mechanisms.append(canonical)

    return " ".join(["v=spf1", *mechanisms, final_all])


def _rewrite_spf_all_qualifier(spf_record: str, new_all: str = "-all") -> str:
    tokens = spf_record.strip().split()
    kept: List[str] = []
    replaced = False
    for tok in tokens:
        _q, body = _extract_spf_qualifier_and_term(tok)
        if body.lower() == "all":
            if not replaced:
                kept.append(new_all)
                replaced = True
        else:
            kept.append(tok)
    if not replaced:
        kept.append(new_all)
    return " ".join(kept)


def _audit_spf(domain: str, resolver: DnsResolver) -> Tuple[SpfAudit, List[AuditIssue], List[FixRecord]]:
    issues: List[AuditIssue] = []
    fixes: List[FixRecord] = []

    res = resolver.query(domain, "TXT")
    if res.error:
        issues.append(
            AuditIssue("ERROR", "SPF", "SPF_DNS_ERROR", f"Failed to query TXT records for SPF: {res.error}")
        )
        return SpfAudit(status="FAIL", score=0), issues, fixes

    txt_values = [str(r.value) for r in res.records if r.qtype == "TXT"]
    spf_records = [t.strip() for t in txt_values if _is_spf_record(t)]

    if not spf_records:
        issues.append(
            AuditIssue(
                "ERROR",
                "SPF",
                "SPF_MISSING",
                f"No v=spf1 TXT record found for {domain}.",
            )
        )
        fixes.append(
            FixRecord(
                category="SPF",
                host=f"{domain}.",
                record_type="TXT",
                ttl=3600,
                value="v=spf1 mx -all",
                reason="Publish an SPF record authorizing legitimate senders and rejecting spoofed mail.",
            )
        )
        return SpfAudit(status="MISSING", score=0), issues, fixes

    duplicate_spf = len(spf_records) > 1
    if duplicate_spf:
        issues.append(
            AuditIssue(
                "ERROR",
                "SPF",
                "SPF_DUPLICATE",
                f"Found {len(spf_records)} SPF (v=spf1) TXT records for {domain}; RFC 7208 requires exactly one (PermError).",
            )
        )
        fixes.append(
            FixRecord(
                category="SPF",
                host=f"{domain}.",
                record_type="TXT",
                ttl=3600,
                value=_merge_spf_records(spf_records),
                reason="Consolidate multiple SPF TXT records into a single v=spf1 record.",
            )
        )

    primary_spf = spf_records[0]
    tokens = primary_spf.split()

    lookup_count = 0
    lookup_steps: List[SpfLookupStep] = []
    broken_includes: List[str] = []
    circular_include = False
    uses_ptr = False
    all_qualifier: Optional[str] = None
    has_redirect = False

    def walk_spf(
        current_domain: str,
        record_text: str,
        depth: int,
        stack: Set[str],
        inherit_all: bool = False,
    ) -> None:
        nonlocal lookup_count, circular_include, uses_ptr, all_qualifier, has_redirect

        if depth > MAX_SPF_RECURSION_DEPTH:
            return

        rec_tokens = record_text.strip().split()
        for tok in rec_tokens[1:]:
            q, body = _extract_spf_qualifier_and_term(tok)
            body_l = body.lower()

            # Check modifiers first (`redirect=`, `exp=`)
            if body_l.startswith("redirect="):
                if depth == 0:
                    has_redirect = True
                target = body.split("=", 1)[1].strip().rstrip(".").lower()
                if not target:
                    continue
                lookup_count += 1
                if "%{" in target:
                    lookup_steps.append(
                        SpfLookupStep(current_domain, tok, 1, depth, "macro redirect target (not expanded)")
                    )
                    continue
                if target in stack:
                    circular_include = True
                    lookup_steps.append(
                        SpfLookupStep(current_domain, tok, 1, depth, f"circular redirect to {target}")
                    )
                    continue
                lookup_steps.append(SpfLookupStep(current_domain, tok, 1, depth))
                sub_res = resolver.query(target, "TXT")
                sub_spfs = [str(r.value).strip() for r in sub_res.records if r.qtype == "TXT" and _is_spf_record(str(r.value))]
                if not sub_spfs or sub_res.error:
                    broken_includes.append(target)
                else:
                    walk_spf(target, sub_spfs[0], depth + 1, stack | {target}, inherit_all=True)
                continue

            if body_l.startswith("exp="):
                # RFC 7208 Section 4.6.4: `exp=` does not count toward the 10-lookup limit
                continue

            if body_l == "all":
                if (depth == 0 or inherit_all) and all_qualifier is None:
                    all_qualifier = q
                continue

            # Mechanisms
            if body_l.startswith("ip4:") or body_l.startswith("ip6:"):
                continue

            if body_l.startswith("include:"):
                target = body.split(":", 1)[1].strip().rstrip(".").lower()
                if not target:
                    continue
                lookup_count += 1
                if "%{" in target:
                    lookup_steps.append(
                        SpfLookupStep(current_domain, tok, 1, depth, "macro include target (not expanded)")
                    )
                    continue
                if target in stack:
                    circular_include = True
                    lookup_steps.append(
                        SpfLookupStep(current_domain, tok, 1, depth, f"circular include to {target}")
                    )
                    continue
                lookup_steps.append(SpfLookupStep(current_domain, tok, 1, depth))
                sub_res = resolver.query(target, "TXT")
                sub_spfs = [str(r.value).strip() for r in sub_res.records if r.qtype == "TXT" and _is_spf_record(str(r.value))]
                if sub_res.error or not sub_spfs:
                    broken_includes.append(target)
                else:
                    walk_spf(target, sub_spfs[0], depth + 1, stack | {target})
                continue

            mech_name = re.split(r"[:/]", body_l, maxsplit=1)[0]
            if mech_name in ("a", "mx", "ptr", "exists"):
                lookup_count += 1
                if mech_name == "ptr":
                    uses_ptr = True
                lookup_steps.append(SpfLookupStep(current_domain, tok, 1, depth))

    walk_spf(domain, primary_spf, 0, {domain})

    exceeds_limit = lookup_count > MAX_SPF_DNS_LOOKUPS
    if exceeds_limit:
        issues.append(
            AuditIssue(
                "ERROR",
                "SPF",
                "SPF_LOOKUP_LIMIT_EXCEEDED",
                f"SPF requires {lookup_count} DNS lookups, exceeding RFC 7208 limit of {MAX_SPF_DNS_LOOKUPS} (causes PermError).",
            )
        )
        if not duplicate_spf:
            fixes.append(
                FixRecord(
                    category="SPF",
                    host=f"{domain}.",
                    record_type="TXT",
                    ttl=3600,
                    value="v=spf1 ip4:<FLATTENED_CIDRS> include:<PRIMARY_ESP> -all",
                    reason=(
                        f"Reduce SPF DNS lookups from {lookup_count} to <=10 by removing unused "
                        "includes or flattening static sender IPs into ip4/ip6 mechanisms."
                    ),
                )
            )

    if circular_include:
        issues.append(
            AuditIssue(
                "ERROR",
                "SPF",
                "SPF_CIRCULAR_INCLUDE",
                "Circular SPF include/redirect loop detected; receiving MTAs will return PermError.",
            )
        )

    if broken_includes:
        issues.append(
            AuditIssue(
                "WARN",
                "SPF",
                "SPF_BROKEN_INCLUDE",
                f"Included/redirected domain(s) missing valid v=spf1 record: {', '.join(broken_includes)}",
            )
        )

    if uses_ptr:
        issues.append(
            AuditIssue(
                "WARN",
                "SPF",
                "SPF_DEPRECATED_PTR",
                "SPF uses the 'ptr' mechanism, which is discouraged/deprecated by RFC 7208 due to slow reverse DNS lookups.",
            )
        )

    if all_qualifier == "+":
        issues.append(
            AuditIssue(
                "ERROR",
                "SPF",
                "SPF_PLUS_ALL",
                "SPF ends with '+all' (allow any host on the internet to spoof this domain!).",
            )
        )
        if not duplicate_spf:
            fixes.append(
                FixRecord(
                    category="SPF",
                    host=f"{domain}.",
                    record_type="TXT",
                    ttl=3600,
                    value=_rewrite_spf_all_qualifier(primary_spf, "-all"),
                    reason="Replace insecure '+all' with '-all' (hardfail) or '~all' (softfail during rollout).",
                )
            )
    elif all_qualifier == "?":
        issues.append(
            AuditIssue(
                "WARN",
                "SPF",
                "SPF_NEUTRAL_ALL",
                "SPF uses '?all' (neutral), providing no spoofing enforcement.",
            )
        )
        if not duplicate_spf:
            fixes.append(
                FixRecord(
                    category="SPF",
                    host=f"{domain}.",
                    record_type="TXT",
                    ttl=3600,
                    value=_rewrite_spf_all_qualifier(primary_spf, "-all"),
                    reason="Strengthen neutral '?all' to '-all' (or '~all').",
                )
            )
    elif all_qualifier == "~":
        issues.append(
            AuditIssue(
                "INFO",
                "SPF",
                "SPF_SOFTFAIL_ALL",
                "SPF uses '~all' (softfail). Consider upgrading to '-all' once all sending sources are verified.",
            )
        )
    elif all_qualifier is None and not has_redirect:
        issues.append(
            AuditIssue(
                "WARN",
                "SPF",
                "SPF_MISSING_ALL",
                "SPF record lacks a terminating 'all' mechanism or 'redirect=' modifier (defaults to neutral).",
            )
        )
        if not duplicate_spf:
            fixes.append(
                FixRecord(
                    category="SPF",
                    host=f"{domain}.",
                    record_type="TXT",
                    ttl=3600,
                    value=_rewrite_spf_all_qualifier(primary_spf, "-all"),
                    reason="Append terminating '-all' mechanism to SPF record.",
                )
            )

    # Calculate SPF score (0..30)
    if duplicate_spf or all_qualifier == "+":
        spf_score = 0
        status = "FAIL"
    else:
        spf_score = 10  # Valid single SPF record present
        if not exceeds_limit and not circular_include:
            spf_score += 10 if not broken_includes else 6
        if all_qualifier == "-":
            spf_score += 10
        elif all_qualifier == "~":
            spf_score += 7
        elif all_qualifier == "?":
            spf_score += 3
        elif has_redirect:
            spf_score += 7
        else:
            spf_score += 2

        if uses_ptr:
            spf_score = max(0, spf_score - 2)

        if exceeds_limit or circular_include:
            status = "FAIL"
        elif any(i.severity == "WARN" for i in issues):
            status = "WARN"
        else:
            status = "PASS"

    return (
        SpfAudit(
            status=status,
            records_found=spf_records,
            duplicate_records=duplicate_spf,
            lookup_count=lookup_count,
            lookup_limit=MAX_SPF_DNS_LOOKUPS,
            exceeds_lookup_limit=exceeds_limit,
            all_qualifier=all_qualifier,
            has_redirect=has_redirect,
            circular_include=circular_include,
            broken_includes=broken_includes,
            uses_ptr=uses_ptr,
            lookup_steps=lookup_steps,
            score=spf_score,
        ),
        issues,
        fixes,
    )


def _is_dmarc_record(txt: str) -> bool:
    stripped = txt.strip()
    return stripped.startswith("v=DMARC1;") or stripped.startswith("v=DMARC1 ") or stripped == "v=DMARC1"


def _parse_tag_list(record: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        chunk = part.strip()
        if not chunk or "=" not in chunk:
            continue
        key, val = chunk.split("=", 1)
        tags[key.strip().lower()] = val.strip()
    return tags


def _build_dmarc_fix_value(existing_tags: Dict[str, str], domain: str) -> str:
    policy = existing_tags.get("p", "").lower()
    target_policy = policy if policy in ("quarantine", "reject") else "quarantine"
    rua = existing_tags.get("rua", "").strip()
    if not rua:
        rua = f"mailto:dmarc-reports@{domain}"
    adkim = existing_tags.get("adkim", "r")
    aspf = existing_tags.get("aspf", "r")
    return f"v=DMARC1; p={target_policy}; rua={rua}; adkim={adkim}; aspf={aspf}; pct=100"


def _audit_dmarc(domain: str, resolver: DnsResolver) -> Tuple[DmarcAudit, List[AuditIssue], List[FixRecord]]:
    issues: List[AuditIssue] = []
    fixes: List[FixRecord] = []

    dmarc_host = f"_dmarc.{domain}"
    res = resolver.query(dmarc_host, "TXT")
    if res.error:
        issues.append(
            AuditIssue("ERROR", "DMARC", "DMARC_DNS_ERROR", f"Failed to query {dmarc_host}: {res.error}")
        )
        return DmarcAudit(status="FAIL", score=0), issues, fixes

    txt_values = [str(r.value) for r in res.records if r.qtype == "TXT"]
    dmarc_records = [t.strip() for t in txt_values if _is_dmarc_record(t)]

    if not dmarc_records:
        issues.append(
            AuditIssue(
                "ERROR",
                "DMARC",
                "DMARC_MISSING",
                f"No v=DMARC1 TXT record found at {dmarc_host}.",
            )
        )
        fixes.append(
            FixRecord(
                category="DMARC",
                host=f"{dmarc_host}.",
                record_type="TXT",
                ttl=3600,
                value=f"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}; adkim=r; aspf=r; pct=100",
                reason="Publish DMARC record with aggregate reporting (upgrade to p=reject after verifying reports).",
            )
        )
        return DmarcAudit(status="MISSING", score=0), issues, fixes

    duplicate_dmarc = len(dmarc_records) > 1
    if duplicate_dmarc:
        issues.append(
            AuditIssue(
                "ERROR",
                "DMARC",
                "DMARC_DUPLICATE",
                f"Multiple ({len(dmarc_records)}) v=DMARC1 records at {dmarc_host}; RFC 7489 ignores all when multiple exist.",
            )
        )

    tags = _parse_tag_list(dmarc_records[0])
    policy_raw = tags.get("p", "").lower()
    policy = policy_raw if policy_raw in ("none", "quarantine", "reject") else None
    sp_raw = tags.get("sp", "").lower()
    sp = sp_raw if sp_raw in ("none", "quarantine", "reject") else None

    pct = 100
    if "pct" in tags:
        try:
            pct = max(0, min(100, int(tags["pct"])))
        except ValueError:
            issues.append(
                AuditIssue("WARN", "DMARC", "DMARC_INVALID_PCT", f"Invalid DMARC pct={tags['pct']!r}.")
            )

    rua_list = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    ruf_list = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]
    adkim = tags.get("adkim", "r").lower()
    aspf = tags.get("aspf", "r").lower()

    valid_rua = [u for u in rua_list if u.lower().startswith("mailto:")]
    if rua_list and not valid_rua:
        issues.append(
            AuditIssue(
                "WARN",
                "DMARC",
                "DMARC_INVALID_RUA",
                f"DMARC rua URIs must use mailto: scheme: {', '.join(rua_list)}",
            )
        )

    if policy is None:
        issues.append(
            AuditIssue(
                "ERROR",
                "DMARC",
                "DMARC_INVALID_POLICY",
                f"DMARC record missing valid 'p=' policy tag (expected reject|quarantine|none, got {policy_raw!r}).",
            )
        )
    elif policy == "none":
        issues.append(
            AuditIssue(
                "WARN",
                "DMARC",
                "DMARC_POLICY_NONE",
                "DMARC policy is 'p=none' (monitoring only — spoofed emails are still delivered).",
            )
        )
    elif policy == "quarantine":
        issues.append(
            AuditIssue(
                "INFO",
                "DMARC",
                "DMARC_POLICY_QUARANTINE",
                "DMARC policy is 'p=quarantine'. Consider tightening to 'p=reject' for full anti-spoofing enforcement.",
            )
        )

    if not valid_rua:
        issues.append(
            AuditIssue(
                "WARN",
                "DMARC",
                "DMARC_MISSING_RUA",
                "DMARC record has no valid 'rua=mailto:...' aggregate reporting URI; delivery failures remain invisible.",
            )
        )

    if policy in ("quarantine", "reject") and pct < 100:
        issues.append(
            AuditIssue(
                "WARN",
                "DMARC",
                "DMARC_PARTIAL_PCT",
                f"DMARC enforcement applies to only pct={pct}% of failing messages (recommend pct=100).",
            )
        )

    if duplicate_dmarc or policy in (None, "none") or not valid_rua:
        fixes.append(
            FixRecord(
                category="DMARC",
                host=f"{dmarc_host}.",
                record_type="TXT",
                ttl=3600,
                value=_build_dmarc_fix_value(tags, domain),
                reason="Ensure single DMARC record with enforced policy (quarantine/reject) and aggregate rua reporting.",
            )
        )

    # Calculate DMARC score (0..30)
    if duplicate_dmarc or policy is None:
        dmarc_score = 0
        status = "FAIL"
    else:
        dmarc_score = 5  # Valid single record present
        if policy == "reject":
            dmarc_score += 17 if pct == 100 else 13
        elif policy == "quarantine":
            dmarc_score += 12 if pct == 100 else 9
        else:  # p=none
            dmarc_score += 3

        if valid_rua:
            dmarc_score += 8

        if policy == "none" or not valid_rua or (policy in ("quarantine", "reject") and pct < 100):
            status = "WARN"
        else:
            status = "PASS"

    return (
        DmarcAudit(
            status=status,
            records_found=dmarc_records,
            duplicate_records=duplicate_dmarc,
            policy=policy,
            subdomain_policy=sp,
            pct=pct,
            rua=rua_list,
            ruf=ruf_list,
            adkim=adkim,
            aspf=aspf,
            score=dmarc_score,
        ),
        issues,
        fixes,
    )


def _estimate_rsa_bits(b64_key: str) -> Optional[int]:
    """Best-effort RSA key size estimate from ASN.1 DER SubjectPublicKeyInfo length."""
    cleaned = re.sub(r"\s+", "", b64_key)
    if len(cleaned) < 64:
        return None
    try:
        der = base64.b64decode(cleaned, validate=True)
    except Exception:
        return None
    # Rough standard SPKI sizes: 1024-bit ~162B, 2048-bit ~294B, 4096-bit ~550B
    if len(der) >= 500:
        return 4096
    if len(der) >= 250:
        return 2048
    if len(der) >= 130:
        return 1024
    return None


def _audit_dkim(
    domain: str,
    resolver: DnsResolver,
    selectors: Sequence[str],
) -> Tuple[DkimAudit, List[AuditIssue], List[FixRecord]]:
    issues: List[AuditIssue] = []
    fixes: List[FixRecord] = []

    clean_selectors: List[str] = []
    seen_sel: Set[str] = set()
    for s in selectors:
        sel = s.strip().rstrip(".")
        if sel and sel.lower() not in seen_sel:
            seen_sel.add(sel.lower())
            clean_selectors.append(sel)

    found_results: List[DkimSelectorResult] = []
    any_active = False
    any_testing_only = False
    any_revoked = False

    for sel in clean_selectors:
        fqdn = f"{sel}._domainkey.{domain}"
        res = resolver.query(fqdn, "TXT")
        if res.error:
            continue

        dkim_txts = [
            str(r.value).strip()
            for r in res.records
            if r.qtype == "TXT" and ("p=" in str(r.value).lower() or "v=dkim1" in str(r.value).lower())
        ]
        if not dkim_txts:
            continue

        raw_txt = dkim_txts[0]
        tags = _parse_tag_list(raw_txt)
        key_type = tags.get("k", "rsa").lower()
        pubkey = tags.get("p", "")
        flags = tags.get("t", "").lower().split(":") if "t" in tags else []

        if "p" not in tags:
            found_results.append(
                DkimSelectorResult(
                    selector=sel,
                    fqdn=fqdn,
                    found=True,
                    status="INVALID",
                    record=raw_txt,
                    key_type=key_type,
                    cnames=res.cnames,
                )
            )
            issues.append(
                AuditIssue("WARN", "DKIM", "DKIM_MISSING_PUBKEY", f"DKIM record at {fqdn} lacks 'p=' tag.")
            )
            continue

        if pubkey == "":
            any_revoked = True
            found_results.append(
                DkimSelectorResult(
                    selector=sel,
                    fqdn=fqdn,
                    found=True,
                    status="REVOKED",
                    record=raw_txt,
                    key_type=key_type,
                    cnames=res.cnames,
                )
            )
            issues.append(
                AuditIssue("INFO", "DKIM", "DKIM_KEY_REVOKED", f"DKIM selector {fqdn} has an empty 'p=' (revoked key).")
            )
            continue

        bits = _estimate_rsa_bits(pubkey) if key_type == "rsa" else None
        if bits is not None and bits < 2048:
            issues.append(
                AuditIssue(
                    "WARN",
                    "DKIM",
                    "DKIM_WEAK_KEY",
                    f"DKIM selector {fqdn} uses a {bits}-bit RSA key; upgrade to >=2048 bits.",
                )
            )

        if "y" in flags:
            any_testing_only = True
            found_results.append(
                DkimSelectorResult(
                    selector=sel,
                    fqdn=fqdn,
                    found=True,
                    status="TESTING",
                    record=raw_txt,
                    key_type=key_type,
                    key_bits=bits,
                    cnames=res.cnames,
                )
            )
            issues.append(
                AuditIssue(
                    "WARN",
                    "DKIM",
                    "DKIM_TESTING_MODE",
                    f"DKIM selector {fqdn} has testing flag 't=y'; remove 't=y' for production signing.",
                )
            )
        else:
            any_active = True
            found_results.append(
                DkimSelectorResult(
                    selector=sel,
                    fqdn=fqdn,
                    found=True,
                    status="ACTIVE",
                    record=raw_txt,
                    key_type=key_type,
                    key_bits=bits,
                    cnames=res.cnames,
                )
            )

    if any_active:
        return (
            DkimAudit(
                status="PASS",
                selectors_probed=clean_selectors,
                selectors_found=found_results,
                score=20,
            ),
            issues,
            fixes,
        )

    if any_testing_only:
        return (
            DkimAudit(
                status="WARN",
                selectors_probed=clean_selectors,
                selectors_found=found_results,
                score=14,
            ),
            issues,
            fixes,
        )

    detail = (
        "Only revoked DKIM key(s) found"
        if any_revoked
        else f"No active DKIM TXT records found across probed selectors ({', '.join(clean_selectors)})"
    )
    issues.append(
        AuditIssue(
            "WARN",
            "DKIM",
            "DKIM_NOT_FOUND",
            f"{detail}. Pass --dkim-selector <name> if your provider uses a custom selector.",
        )
    )
    fixes.append(
        FixRecord(
            category="DKIM",
            host=f"{clean_selectors[0] if clean_selectors else 'default'}._domainkey.{domain}.",
            record_type="TXT",
            ttl=3600,
            value="v=DKIM1; k=rsa; p=<YOUR_2048_BIT_BASE64_PUBLIC_KEY>",
            reason="Publish a 2048-bit DKIM public key generated by your email provider / MTA.",
        )
    )
    return (
        DkimAudit(
            status="MISSING",
            selectors_probed=clean_selectors,
            selectors_found=found_results,
            score=0,
        ),
        issues,
        fixes,
    )


def audit_domain(
    raw_domain: str,
    resolver: Optional[DnsResolver] = None,
    dkim_selectors: Optional[Sequence[str]] = None,
) -> DomainAuditResult:
    """Run full MX, SPF, DMARC, and DKIM audit for a single domain."""
    domain = normalize_domain(raw_domain)
    active_resolver = resolver or NativeDnsClient()
    selectors = list(dkim_selectors) if dkim_selectors else list(DEFAULT_DKIM_SELECTORS)

    mx_res, mx_issues, mx_fixes = _audit_mx(domain, active_resolver)
    spf_res, spf_issues, spf_fixes = _audit_spf(domain, active_resolver)
    dmarc_res, dmarc_issues, dmarc_fixes = _audit_dmarc(domain, active_resolver)
    dkim_res, dkim_issues, dkim_fixes = _audit_dkim(domain, active_resolver, selectors)

    total_score = max(0, min(100, mx_res.score + spf_res.score + dmarc_res.score + dkim_res.score))
    grade = _score_to_grade(total_score)

    return DomainAuditResult(
        domain=domain,
        score=total_score,
        grade=grade,
        mx=mx_res,
        spf=spf_res,
        dmarc=dmarc_res,
        dkim=dkim_res,
        issues=mx_issues + spf_issues + dmarc_issues + dkim_issues,
        fixes=mx_fixes + spf_fixes + dmarc_fixes + dkim_fixes,
    )


# ---------------------------------------------------------------------------
# Input Loading & Output Formatters
# ---------------------------------------------------------------------------


def load_domains_from_file(path_str: str) -> List[str]:
    """Load domain names from a plain-text or CSV file (`-` for stdin)."""
    if path_str == "-":
        raw_lines = sys.stdin.read().splitlines()
    else:
        path = Path(path_str)
        if not path.is_file():
            raise FileNotFoundError(f"Domains file not found: {path_str}")
        raw_lines = path.read_text(encoding="utf-8-sig").splitlines()

    domains: List[str] = []
    saw_data_line = False
    for line in raw_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Support CSV files where first column is domain
        if "," in stripped:
            first_col = stripped.split(",", 1)[0].strip().strip('"').strip("'")
            if not saw_data_line and first_col.lower() in ("domain", "domains", "host", "hostname"):
                saw_data_line = True
                continue
            candidate = first_col
        else:
            if not saw_data_line and stripped.lower() in ("domain", "domains", "host", "hostname"):
                saw_data_line = True
                continue
            candidate = stripped
        saw_data_line = True
        domains.append(normalize_domain(candidate))

    return domains


def format_text_report(
    results: Sequence[DomainAuditResult],
    min_score: Optional[int] = None,
    include_fixes: bool = True,
) -> str:
    """Format audit results as a crisp human-readable report."""
    lines: List[str] = []

    if len(results) > 1:
        avg_score = round(sum(r.score for r in results) / len(results), 1)
        lines.append(
            f"Deliverability Audit Summary | Domains: {len(results)} | Avg Score: {avg_score}/100"
            + (f" | Min Score Gate: {min_score}" if min_score is not None else "")
        )
        lines.append("")
        header = "Domain                         | Score   | Grade | MX   | SPF (Lookups) | DMARC           | DKIM"
        sep = "-------------------------------+---------+-------+------+---------------+-----------------+--------"
        lines.append(header)
        lines.append(sep)
        for r in results:
            spf_col = f"{r.spf.status} ({r.spf.lookup_count}/{r.spf.lookup_limit})"
            dmarc_col = f"{r.dmarc.status} ({r.dmarc.policy or '-'})"
            dkim_col = f"{r.dkim.status}"
            lines.append(
                f"{r.domain:<30} | {r.score:>3}/100 |   {r.grade}   | {r.mx.status:<4} | "
                f"{spf_col:<13} | {dmarc_col:<15} | {dkim_col}"
            )
        lines.append("")

    for r in results:
        gate_str = ""
        if min_score is not None:
            gate_str = f" | Gate ({min_score}): {'PASS' if r.score >= min_score else 'FAIL'}"
        lines.append(f"=== {r.domain} | Score: {r.score}/100 (Grade {r.grade}){gate_str} ===")

        # MX
        mx_summary = (
            ", ".join(f"{m.preference} {m.exchange}" for m in r.mx.records)
            if r.mx.records
            else "none"
        )
        lines.append(f"[MX    {r.mx.score:>2}/{r.mx.max_score}] {r.mx.status:<7} | Hosts: {mx_summary}")

        # SPF
        all_str = f"{r.spf.all_qualifier}all" if r.spf.all_qualifier else ("redirect" if r.spf.has_redirect else "none")
        lines.append(
            f"[SPF   {r.spf.score:>2}/{r.spf.max_score}] {r.spf.status:<7} | "
            f"Lookups: {r.spf.lookup_count}/{r.spf.lookup_limit} | Policy: {all_str}"
            + (f" | Duplicates: {len(r.spf.records_found)}" if r.spf.duplicate_records else "")
        )
        if r.spf.records_found:
            lines.append(f"  Record : {r.spf.records_found[0]}")
        if r.spf.lookup_steps:
            breakdown = ", ".join(
                f"{step.mechanism}" + (f" [{step.note}]" if step.note else "")
                for step in r.spf.lookup_steps
            )
            lines.append(f"  Lookups: {breakdown}")

        # DMARC
        rua_str = ", ".join(r.dmarc.rua) if r.dmarc.rua else "none"
        policy_str = r.dmarc.policy or ("invalid" if r.dmarc.records_found else "missing")
        lines.append(
            f"[DMARC {r.dmarc.score:>2}/{r.dmarc.max_score}] {r.dmarc.status:<7} | "
            f"Policy: {policy_str} | pct: {r.dmarc.pct}% | rua: {rua_str}"
        )
        if r.dmarc.records_found:
            lines.append(f"  Record : {r.dmarc.records_found[0]}")

        # DKIM
        if r.dkim.selectors_found:
            found_desc = ", ".join(
                f"{s.selector} ({s.status}"
                + (f", {s.key_type}" if s.key_type else "")
                + (f"-{s.key_bits}b" if s.key_bits else "")
                + ")"
                for s in r.dkim.selectors_found
            )
        else:
            found_desc = f"none found (probed: {', '.join(r.dkim.selectors_probed)})"
        lines.append(f"[DKIM  {r.dkim.score:>2}/{r.dkim.max_score}] {r.dkim.status:<7} | Selectors: {found_desc}")

        if r.issues:
            lines.append("Findings:")
            for issue in r.issues:
                lines.append(f"  - [{issue.severity}] ({issue.category}/{issue.code}) {issue.message}")

        if include_fixes and r.fixes:
            lines.append("Copy-Paste DNS Fix Records:")
            for fix in r.fixes:
                lines.append(f"  ; {fix.category}: {fix.reason}")
                lines.append(f"  {fix.format_zone_line()}")

        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_json_report(
    results: Sequence[DomainAuditResult],
    min_score: Optional[int] = None,
) -> str:
    """Format audit results as structured JSON."""
    passed = True if min_score is None else all(r.score >= min_score for r in results)
    avg_score = round(sum(r.score for r in results) / len(results), 2) if results else 0.0
    payload = {
        "schema_version": "1.0",
        "min_score": min_score,
        "passed": passed,
        "summary": {
            "total_domains": len(results),
            "average_score": avg_score,
            "passing_gate": sum(1 for r in results if min_score is None or r.score >= min_score),
            "failing_gate": sum(1 for r in results if min_score is not None and r.score < min_score),
        },
        "domains": [
            {
                **asdict(r),
                "fixes": [
                    {**asdict(f), "zone_record": f.format_zone_line()} for f in r.fixes
                ],
            }
            for r in results
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def format_csv_report(
    results: Sequence[DomainAuditResult],
    min_score: Optional[int] = None,
) -> str:
    """Format audit results as RFC-4180 CSV (one row per audited domain)."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        [
            "domain",
            "score",
            "grade",
            "passed",
            "mx_status",
            "mx_hosts",
            "spf_status",
            "spf_lookups",
            "spf_all",
            "spf_duplicate",
            "dmarc_status",
            "dmarc_policy",
            "dmarc_rua",
            "dkim_status",
            "dkim_selectors_found",
            "issues_count",
            "fix_records_count",
            "recommended_fixes",
        ]
    )
    for r in results:
        passed = True if min_score is None else (r.score >= min_score)
        writer.writerow(
            [
                r.domain,
                r.score,
                r.grade,
                "true" if passed else "false",
                r.mx.status,
                "; ".join(f"{m.preference} {m.exchange}" for m in r.mx.records),
                r.spf.status,
                r.spf.lookup_count,
                f"{r.spf.all_qualifier}all" if r.spf.all_qualifier else ("redirect" if r.spf.has_redirect else "none"),
                "true" if r.spf.duplicate_records else "false",
                r.dmarc.status,
                r.dmarc.policy or "",
                "; ".join(r.dmarc.rua),
                r.dkim.status,
                "; ".join(f"{s.selector}:{s.status}" for s in r.dkim.selectors_found),
                len(r.issues),
                len(r.fixes),
                " | ".join(f.format_zone_line() for f in r.fixes),
            ]
        )
    return buf.getvalue()


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deliverability_cli.py",
        description=(
            "Zero-dependency Python CLI with a native RFC 1035 DNS client to audit "
            "domain MX, SPF (10-lookup RFC 7208 limit), DMARC, and DKIM deliverability hygiene."
        ),
    )
    parser.add_argument(
        "domains",
        nargs="*",
        help="Optional positional domain name(s) to audit.",
    )
    parser.add_argument(
        "-d",
        "--domain",
        dest="opt_domains",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="Target domain name to audit (repeatable).",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="domain_file",
        metavar="FILE",
        help="Path to text/CSV file of domains (one per line, '-' for stdin).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "csv"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=None,
        metavar="N",
        help="Fail with exit code 1 if any audited domain scores below N (0-100).",
    )
    parser.add_argument(
        "--dkim-selector",
        action="append",
        default=[],
        metavar="SELECTOR",
        help="DKIM selector to check (repeatable or comma-separated; defaults to common selectors).",
    )
    parser.add_argument(
        "--dns-server",
        action="append",
        default=[],
        metavar="IP",
        help="DNS resolver IP address (repeatable; defaults to 1.1.1.1, 8.8.8.8).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        metavar="SEC",
        help="Per-query DNS socket timeout in seconds (default: 3.0).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        metavar="N",
        help="Number of DNS query retries after initial attempt (default: 1).",
    )
    parser.add_argument(
        "--no-fixes",
        action="store_true",
        help="Omit copy-paste DNS fix records in text output.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    resolver: Optional[DnsResolver] = None,
    stdout: Optional[Any] = None,
    stderr: Optional[Any] = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = build_arg_parser()

    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2

    if args.min_score is not None and not (0 <= args.min_score <= 100):
        print("Error: --min-score must be between 0 and 100.", file=err)
        return 2

    if args.timeout <= 0:
        print("Error: --timeout must be greater than 0.", file=err)
        return 2

    raw_domains: List[str] = []
    raw_domains.extend(args.opt_domains)
    raw_domains.extend(args.domains)

    domains: List[str] = []
    seen_domains: Set[str] = set()

    try:
        for d in raw_domains:
            norm = normalize_domain(d)
            if norm not in seen_domains:
                seen_domains.add(norm)
                domains.append(norm)

        if args.domain_file:
            for d in load_domains_from_file(args.domain_file):
                if d not in seen_domains:
                    seen_domains.add(d)
                    domains.append(d)
    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"Error: {exc}", file=err)
        return 2

    if not domains:
        print("Error: Provide at least one domain via --domain, positional argument, or --file.", file=err)
        return 2

    selectors: List[str] = []
    for item in args.dkim_selector:
        for part in item.split(","):
            s = part.strip()
            if s:
                selectors.append(s)

    dns_servers = tuple(args.dns_server) if args.dns_server else DEFAULT_DNS_SERVERS
    active_resolver = resolver or NativeDnsClient(
        servers=dns_servers,
        timeout=args.timeout,
        retries=args.retries,
    )

    results = [
        audit_domain(
            d,
            resolver=active_resolver,
            dkim_selectors=selectors or DEFAULT_DKIM_SELECTORS,
        )
        for d in domains
    ]

    if args.format == "json":
        out.write(format_json_report(results, min_score=args.min_score))
    elif args.format == "csv":
        out.write(format_csv_report(results, min_score=args.min_score))
    else:
        out.write(
            format_text_report(
                results,
                min_score=args.min_score,
                include_fixes=not args.no_fixes,
            )
        )

    if args.min_score is not None and any(r.score < args.min_score for r in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
