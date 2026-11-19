import base64
import csv
import io
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import deliverability_cli as cli


def _build_txt_rdata(chunks):
    out = bytearray()
    for ch in chunks:
        raw = ch.encode("utf-8") if isinstance(ch, str) else ch
        out.append(len(raw))
        out.extend(raw)
    return bytes(out)


def _build_dns_response_packet(
    tx_id: int,
    qname: str,
    qtype: int,
    answers: list,
    rcode: int = 0,
    tc: bool = False,
) -> bytes:
    """
    Helper to craft raw RFC 1035 DNS response packets with pointer compression.
    `answers` items: tuple `(rtype, rdata_bytes, use_qname_pointer: bool)` or custom.
    """
    flags = 0x8180 | (0x0200 if tc else 0) | (rcode & 0x0F)
    header = struct.pack("!HHHHHH", tx_id, flags, 1, len(answers), 0, 0)
    question = cli.encode_dns_name(qname) + struct.pack("!HH", qtype, cli.QCLASS_IN)
    body = bytearray(header + question)

    for rr_type, rdata, use_ptr in answers:
        if use_ptr:
            # 0xC00C points directly to QNAME at byte offset 12 (right after header)
            body.extend(b"\xc0\x0c")
        else:
            body.extend(cli.encode_dns_name(qname))
        body.extend(struct.pack("!HHIH", rr_type, cli.QCLASS_IN, 300, len(rdata)))
        body.extend(rdata)
    return bytes(body)


class TestRfc1035WireProtocol(unittest.TestCase):
    def test_build_query_and_parse_compressed_txt_response(self):
        tx_id, query_pkt = cli.build_dns_query("example.com", "TXT", tx_id=0x1234)
        self.assertEqual(tx_id, 0x1234)
        self.assertEqual(query_pkt[:2], b"\x12\x34")

        part1 = "v=spf1 include:_spf.google.com "
        part2 = "ip4:192.0.2.0/24 -all"
        rdata = _build_txt_rdata([part1, part2])
        resp = _build_dns_response_packet(
            tx_id=0x1234,
            qname="example.com",
            qtype=cli.QTYPE_IDS["TXT"],
            answers=[(cli.QTYPE_IDS["TXT"], rdata, True)],
        )

        rcode, truncated, records = cli.parse_dns_response(resp, expected_tx_id=0x1234)
        self.assertEqual(rcode, 0)
        self.assertFalse(truncated)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].name, "example.com")
        self.assertEqual(records[0].qtype, "TXT")
        self.assertEqual(records[0].value, part1 + part2)

    def test_parse_mx_with_compression_pointer_in_exchange(self):
        # Question: example.com at offset 12
        # MX RR uses pointer 0xC00C for owner, and RDATA = pref(10) + "mail" label + pointer 0xC00C -> "mail.example.com"
        tx_id = 0x5678
        flags = 0x8180
        header = struct.pack("!HHHHHH", tx_id, flags, 1, 1, 0, 0)
        question = cli.encode_dns_name("example.com") + struct.pack("!HH", cli.QTYPE_IDS["MX"], cli.QCLASS_IN)
        mx_rdata = struct.pack("!H", 10) + b"\x04mail\xc0\x0c"
        answer = b"\xc0\x0c" + struct.pack("!HHIH", cli.QTYPE_IDS["MX"], cli.QCLASS_IN, 600, len(mx_rdata)) + mx_rdata
        packet = header + question + answer

        rcode, _tc, records = cli.parse_dns_response(packet, expected_tx_id=tx_id)
        self.assertEqual(rcode, 0)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].value, cli.MxValue(preference=10, exchange="mail.example.com"))

    def test_decode_dns_name_pointer_loop_raises_protocol_error(self):
        # 12-byte header + pointer at offset 12 pointing to offset 12 (0xC00C)
        packet = b"\x00" * 12 + b"\xc0\x0c"
        with self.assertRaises(cli.DnsProtocolError):
            cli.decode_dns_name(packet, 12)

    def test_parse_dns_response_rejects_txid_mismatch_and_short_packet(self):
        with self.assertRaises(cli.DnsProtocolError):
            cli.parse_dns_response(b"\x00\x01\x02")

        resp = _build_dns_response_packet(
            tx_id=0xAAAA,
            qname="example.com",
            qtype=cli.QTYPE_IDS["TXT"],
            answers=[],
        )
        with self.assertRaises(cli.DnsProtocolError):
            cli.parse_dns_response(resp, expected_tx_id=0xBBBB)

    def test_native_dns_client_udp_and_tcp_fallback_on_tc_bit(self):
        # Spin up ephemeral local UDP + TCP servers on the same localhost port
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(("127.0.0.1", 0))
        port = udp_sock.getsockname()[1]

        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.bind(("127.0.0.1", port))
        tcp_sock.listen(2)

        def udp_worker():
            data, addr = udp_sock.recvfrom(2048)
            req_tx_id = struct.unpack("!H", data[:2])[0]
            # Respond with TC=1 (truncated) over UDP to trigger TCP fallback
            trunc_resp = _build_dns_response_packet(
                tx_id=req_tx_id,
                qname="example.com",
                qtype=cli.QTYPE_IDS["TXT"],
                answers=[],
                tc=True,
            )
            udp_sock.sendto(trunc_resp, addr)

        def tcp_worker():
            conn, _ = tcp_sock.accept()
            with conn:
                len_hdr = conn.recv(2)
                qlen = struct.unpack("!H", len_hdr)[0]
                qdata = conn.recv(qlen)
                req_tx_id = struct.unpack("!H", qdata[:2])[0]
                full_resp = _build_dns_response_packet(
                    tx_id=req_tx_id,
                    qname="example.com",
                    qtype=cli.QTYPE_IDS["TXT"],
                    answers=[(cli.QTYPE_IDS["TXT"], _build_txt_rdata(["v=spf1 -all"]), True)],
                    tc=False,
                )
                conn.sendall(struct.pack("!H", len(full_resp)) + full_resp)

        t_udp = threading.Thread(target=udp_worker, daemon=True)
        t_tcp = threading.Thread(target=tcp_worker, daemon=True)
        t_udp.start()
        t_tcp.start()

        try:
            client = cli.NativeDnsClient(servers=("127.0.0.1",), port=port, timeout=2.0, retries=0)
            res = client.query("example.com", "TXT")
            self.assertIsNone(res.error)
            self.assertEqual(len(res.records), 1)
            self.assertEqual(res.records[0].value, "v=spf1 -all")
        finally:
            udp_sock.close()
            tcp_sock.close()
            t_udp.join(timeout=1.0)
            t_tcp.join(timeout=1.0)


class TestDomainNormalizationAndInput(unittest.TestCase):
    def test_normalize_domain_variants(self):
        self.assertEqual(cli.normalize_domain("Example.COM."), "example.com")
        self.assertEqual(cli.normalize_domain("https://Sub.Example.com/login"), "sub.example.com")
        self.assertEqual(cli.normalize_domain("ops@Mail.Example.org"), "mail.example.org")
        with self.assertRaises(ValueError):
            cli.normalize_domain("localhost")
        with self.assertRaises(ValueError):
            cli.normalize_domain("   ")

    def test_load_domains_from_file_txt_and_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "domains.csv"
            p.write_text(
                "# Comment line\n"
                "domain,owner\n"
                "\n"
                "acme.com,team-a\n"
                "https://beta.example.org/path,team-b\n",
                encoding="utf-8",
            )
            loaded = cli.load_domains_from_file(str(p))
            self.assertEqual(loaded, ["acme.com", "beta.example.org"])


class TestMxAudit(unittest.TestCase):
    def test_healthy_mx_sorted_by_preference(self):
        resolver = cli.MockDnsResolver(
            {
                ("example.com", "MX"): [(20, "alt2.mail.example.com."), (10, "ALT1.MAIL.EXAMPLE.COM.")],
            }
        )
        res = cli.audit_domain("example.com", resolver=resolver)
        self.assertEqual(res.mx.status, "PASS")
        self.assertEqual(res.mx.score, 20)
        self.assertEqual(res.mx.records[0], cli.MxValue(10, "alt1.mail.example.com"))
        self.assertEqual(res.mx.records[1], cli.MxValue(20, "alt2.mail.example.com"))

    def test_missing_mx_and_null_mx(self):
        missing_res = cli.audit_domain("nomx.example", resolver=cli.MockDnsResolver())
        self.assertEqual(missing_res.mx.status, "MISSING")
        self.assertEqual(missing_res.mx.score, 0)
        self.assertTrue(any(f.category == "MX" and f.record_type == "MX" for f in missing_res.fixes))

        null_resolver = cli.MockDnsResolver({("null.example", "MX"): [(0, ".")]})
        null_res = cli.audit_domain("null.example", resolver=null_resolver)
        self.assertTrue(null_res.mx.null_mx)
        self.assertEqual(null_res.mx.status, "WARN")
        self.assertEqual(null_res.mx.score, 0)


class TestSpfAudit(unittest.TestCase):
    def test_healthy_spf_with_exactly_10_recursive_lookups(self):
        # Root: 1 include + 1 mx + 1 a = 3 lookups at root
        # inc1: 3 includes (3) + inc1a..c (0) + 4 a records? Let's count cleanly:
        # root: include:a.spf (1) + include:b.spf (1) + mx (1) + ip4:1.1.1.1 (0) + exp=explain.spf (0) = 3
        # a.spf: a (1) + mx (1) + include:c.spf (1) = 3
        # b.spf: a (1) + mx (1) + exists:x.example (1) = 3
        # c.spf: a (1) = 1
        # Total = 3 + 3 + 3 + 1 = 10 lookups (exact RFC 7208 boundary!)
        resolver = cli.MockDnsResolver(
            {
                ("exact10.example", "MX"): [(10, "mail.exact10.example")],
                ("exact10.example", "TXT"): [
                    "google-site-verification=abc123",
                    "v=spf1 include:a.spf.example include:b.spf.example mx ip4:192.0.2.0/24 ip6:2001:db8::/32 exp=exp.example -all",
                ],
                ("a.spf.example", "TXT"): ["v=spf1 a mx include:c.spf.example ~all"],
                ("b.spf.example", "TXT"): ["v=spf1 a mx exists:%{i}.rbl.example ~all"],
                ("c.spf.example", "TXT"): ["v=spf1 a -all"],
                ("_dmarc.exact10.example", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@exact10.example"],
                ("google._domainkey.exact10.example", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"],
            }
        )
        res = cli.audit_domain("exact10.example", resolver=resolver)
        self.assertEqual(res.spf.lookup_count, 10)
        self.assertFalse(res.spf.exceeds_lookup_limit)
        self.assertEqual(res.spf.status, "PASS")
        self.assertEqual(res.spf.score, 30)
        self.assertEqual(res.score, 100)
        self.assertEqual(res.grade, "A")

    def test_spf_exceeds_10_lookup_limit_recursively(self):
        resolver = cli.MockDnsResolver(
            {
                ("over10.example", "TXT"): [
                    "v=spf1 include:inc1.example include:inc2.example a mx exists:chk.example -all"
                ],
                ("inc1.example", "TXT"): ["v=spf1 a mx include:deep1.example ~all"],
                ("deep1.example", "TXT"): ["v=spf1 a mx a:relay.example ~all"],
                ("inc2.example", "TXT"): ["v=spf1 a mx ~all"],
            }
        )
        # root: 5 lookups; inc1: 3; deep1: 3; inc2: 2 -> total 13 lookups
        res = cli.audit_domain("over10.example", resolver=resolver)
        self.assertEqual(res.spf.lookup_count, 13)
        self.assertTrue(res.spf.exceeds_lookup_limit)
        self.assertEqual(res.spf.status, "FAIL")
        self.assertTrue(any(i.code == "SPF_LOOKUP_LIMIT_EXCEEDED" for i in res.issues))
        self.assertTrue(any(f.category == "SPF" for f in res.fixes))

    def test_duplicate_spf_records_flagged_and_merged_fix_generated(self):
        resolver = cli.MockDnsResolver(
            {
                ("dup.example", "TXT"): [
                    "v=spf1 include:_spf.google.com ~all",
                    "v=spf1 include:_spf.google.com include:sendgrid.net -all",
                ]
            }
        )
        res = cli.audit_domain("dup.example", resolver=resolver)
        self.assertTrue(res.spf.duplicate_records)
        self.assertEqual(res.spf.status, "FAIL")
        self.assertEqual(res.spf.score, 0)
        self.assertTrue(any(i.code == "SPF_DUPLICATE" for i in res.issues))
        spf_fixes = [f for f in res.fixes if f.category == "SPF"]
        self.assertEqual(len(spf_fixes), 1)
        self.assertEqual(
            spf_fixes[0].value,
            "v=spf1 include:_spf.google.com include:sendgrid.net -all",
        )

    def test_spf_plus_all_and_bare_all_critical_fail(self):
        for rec in ("v=spf1 mx +all", "v=spf1 mx all"):
            resolver = cli.MockDnsResolver({("open.example", "TXT"): [rec]})
            res = cli.audit_domain("open.example", resolver=resolver)
            self.assertEqual(res.spf.all_qualifier, "+")
            self.assertEqual(res.spf.status, "FAIL")
            self.assertEqual(res.spf.score, 0)
            self.assertTrue(any(i.code == "SPF_PLUS_ALL" for i in res.issues))
            spf_fixes = [f for f in res.fixes if f.category == "SPF"]
            self.assertEqual(spf_fixes[0].value, "v=spf1 mx -all")

    def test_spf_circular_include_handled_safely_and_ptr_warned(self):
        resolver = cli.MockDnsResolver(
            {
                ("loop.example", "TXT"): ["v=spf1 ptr include:b.loop.example -all"],
                ("b.loop.example", "TXT"): ["v=spf1 include:loop.example ~all"],
            }
        )
        res = cli.audit_domain("loop.example", resolver=resolver)
        self.assertTrue(res.spf.circular_include)
        self.assertTrue(res.spf.uses_ptr)
        self.assertEqual(res.spf.status, "FAIL")
        codes = {i.code for i in res.issues}
        self.assertIn("SPF_CIRCULAR_INCLUDE", codes)
        self.assertIn("SPF_DEPRECATED_PTR", codes)

    def test_spf_redirect_modifier_inherits_policy(self):
        resolver = cli.MockDnsResolver(
            {
                ("alias.example", "TXT"): ["v=spf1 redirect=_spf.primary.example"],
                ("_spf.primary.example", "TXT"): ["v=spf1 ip4:198.51.100.10 -all"],
            }
        )
        res = cli.audit_domain("alias.example", resolver=resolver)
        self.assertTrue(res.spf.has_redirect)
        self.assertEqual(res.spf.lookup_count, 1)
        self.assertEqual(res.spf.all_qualifier, "-")
        self.assertEqual(res.spf.score, 30)
        self.assertEqual(res.spf.status, "PASS")


class TestDmarcAudit(unittest.TestCase):
    def test_dmarc_reject_with_rua_scores_full_points(self):
        resolver = cli.MockDnsResolver(
            {
                ("_dmarc.strong.example", "TXT"): [
                    "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100; rua=mailto:dmarc@strong.example"
                ]
            }
        )
        res = cli.audit_domain("strong.example", resolver=resolver)
        self.assertEqual(res.dmarc.status, "PASS")
        self.assertEqual(res.dmarc.policy, "reject")
        self.assertEqual(res.dmarc.score, 30)

    def test_dmarc_none_and_missing_rua_warns_with_fix(self):
        resolver = cli.MockDnsResolver(
            {("_dmarc.weak.example", "TXT"): ["v=DMARC1; p=none;"]}
        )
        res = cli.audit_domain("weak.example", resolver=resolver)
        self.assertEqual(res.dmarc.status, "WARN")
        self.assertEqual(res.dmarc.policy, "none")
        codes = {i.code for i in res.issues}
        self.assertIn("DMARC_POLICY_NONE", codes)
        self.assertIn("DMARC_MISSING_RUA", codes)
        dmarc_fix = [f for f in res.fixes if f.category == "DMARC"][0]
        self.assertIn("p=quarantine", dmarc_fix.value)
        self.assertIn("rua=mailto:dmarc-reports@weak.example", dmarc_fix.value)

    def test_dmarc_duplicate_records_fail(self):
        resolver = cli.MockDnsResolver(
            {
                ("_dmarc.dup.example", "TXT"): [
                    "v=DMARC1; p=reject; rua=mailto:a@dup.example",
                    "v=DMARC1; p=none;",
                ]
            }
        )
        res = cli.audit_domain("dup.example", resolver=resolver)
        self.assertTrue(res.dmarc.duplicate_records)
        self.assertEqual(res.dmarc.status, "FAIL")
        self.assertEqual(res.dmarc.score, 0)
        self.assertTrue(any(i.code == "DMARC_DUPLICATE" for i in res.issues))

    def test_dmarc_quarantine_partial_pct(self):
        resolver = cli.MockDnsResolver(
            {
                ("_dmarc.part.example", "TXT"): [
                    "v=DMARC1; p=quarantine; pct=25; rua=mailto:sec@part.example"
                ]
            }
        )
        res = cli.audit_domain("part.example", resolver=resolver)
        self.assertEqual(res.dmarc.status, "WARN")
        self.assertEqual(res.dmarc.pct, 25)
        self.assertTrue(any(i.code == "DMARC_PARTIAL_PCT" for i in res.issues))


class TestDkimAudit(unittest.TestCase):
    def test_dkim_resolved_via_cname_chain(self):
        # Simulate Microsoft 365 style CNAME -> TXT DKIM key (2048-bit DER size ~294 bytes)
        fake_2048_b64 = base64.b64encode(b"\x30" * 294).decode("ascii")
        resolver = cli.MockDnsResolver(
            {
                ("selector1._domainkey.corp.example", "CNAME"): "selector1-corp-example._domainkey.mail.provider.net",
                ("selector1-corp-example._domainkey.mail.provider.net", "TXT"): [
                    f"v=DKIM1; k=rsa; p={fake_2048_b64}"
                ],
            }
        )
        res = cli.audit_domain("corp.example", resolver=resolver)
        self.assertEqual(res.dkim.status, "PASS")
        self.assertEqual(res.dkim.score, 20)
        self.assertEqual(len(res.dkim.selectors_found), 1)
        sel = res.dkim.selectors_found[0]
        self.assertEqual(sel.selector, "selector1")
        self.assertEqual(sel.status, "ACTIVE")
        self.assertEqual(sel.key_bits, 2048)
        self.assertEqual(sel.cnames, ["selector1-corp-example._domainkey.mail.provider.net"])

    def test_dkim_revoked_testing_and_weak_1024bit_keys(self):
        fake_1024_b64 = base64.b64encode(b"\x30" * 162).decode("ascii")
        resolver = cli.MockDnsResolver(
            {
                ("old._domainkey.k.example", "TXT"): ["v=DKIM1; p="],
                ("beta._domainkey.k.example", "TXT"): [f"v=DKIM1; k=rsa; t=y; p={fake_1024_b64}"],
            }
        )
        res = cli.audit_domain("k.example", resolver=resolver, dkim_selectors=["old", "beta"])
        self.assertEqual(res.dkim.status, "WARN")
        self.assertEqual(res.dkim.score, 14)
        codes = {i.code for i in res.issues}
        self.assertIn("DKIM_KEY_REVOKED", codes)
        self.assertIn("DKIM_TESTING_MODE", codes)
        self.assertIn("DKIM_WEAK_KEY", codes)


class TestCliIntegrationAndFormats(unittest.TestCase):
    def _sample_resolver(self):
        return cli.MockDnsResolver(
            {
                ("good.example", "MX"): [(10, "mx.good.example")],
                ("good.example", "TXT"): ["v=spf1 ip4:203.0.113.10 -all"],
                ("_dmarc.good.example", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@good.example"],
                ("google._domainkey.good.example", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"],
                ("bad.example", "MX"): [],
                ("bad.example", "TXT"): ["v=spf1 +all"],
            }
        )

    def test_cli_text_output_includes_copy_paste_fixes_and_min_score_gate(self):
        out = io.StringIO()
        err = io.StringIO()
        rc = cli.main(
            ["--domain", "bad.example", "--format", "text", "--min-score", "80"],
            resolver=self._sample_resolver(),
            stdout=out,
            stderr=err,
        )
        text = out.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("bad.example", text)
        self.assertIn("Copy-Paste DNS Fix Records:", text)
        self.assertIn("bad.example.  3600  IN  TXT", text)
        self.assertIn("v=spf1 -all", text)

    def test_cli_file_json_output_and_passing_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            dom_file = Path(tmp) / "targets.txt"
            dom_file.write_text("good.example\n", encoding="utf-8")

            out = io.StringIO()
            err = io.StringIO()
            rc = cli.main(
                ["--file", str(dom_file), "--format", "json", "--min-score", "90"],
                resolver=self._sample_resolver(),
                stdout=out,
                stderr=err,
            )
            self.assertEqual(rc, 0)
            payload = json.loads(out.getvalue())
            self.assertTrue(payload["passed"])
            self.assertEqual(payload["summary"]["total_domains"], 1)
            self.assertEqual(payload["domains"][0]["score"], 100)
            self.assertEqual(payload["domains"][0]["grade"], "A")

    def test_cli_csv_output_multi_domain(self):
        out = io.StringIO()
        err = io.StringIO()
        rc = cli.main(
            ["-d", "good.example", "-d", "bad.example", "--format", "csv", "--min-score", "50"],
            resolver=self._sample_resolver(),
            stdout=out,
            stderr=err,
        )
        self.assertEqual(rc, 1)
        rows = list(csv.DictReader(io.StringIO(out.getvalue())))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["domain"], "good.example")
        self.assertEqual(rows[0]["passed"], "true")
        self.assertEqual(rows[1]["domain"], "bad.example")
        self.assertEqual(rows[1]["passed"], "false")

    def test_cli_invalid_arguments_return_exit_code_2(self):
        out = io.StringIO()
        err = io.StringIO()
        self.assertEqual(cli.main([], resolver=self._sample_resolver(), stdout=out, stderr=err), 2)
        self.assertEqual(
            cli.main(["-d", "good.example", "--min-score", "150"], resolver=self._sample_resolver(), stdout=out, stderr=err),
            2,
        )
        self.assertEqual(
            cli.main(["--file", "nonexistent_domains_12345.txt"], resolver=self._sample_resolver(), stdout=out, stderr=err),
            2,
        )


if __name__ == "__main__":
    unittest.main()
