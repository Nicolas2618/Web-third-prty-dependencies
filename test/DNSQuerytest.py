
import unittest
import struct
import socket
from unittest.mock import patch, MagicMock

from src.DNSQuery import create_dns_query, parse_dns_response, dns_query, get_ns

#region Domains
# ── Domains to loop over ─────────────────────────────────────────────────────
DOMAINS = [
    "google.com",
    "github.com",
    "googleapis.com",
    "cloudflare.com",
    "gstatic.com",
    "apple.com",
    "microsoft.com",
    "facebook.com",
    "amazonaws.com",
    "googlevideo.com",
    "fbcdn.net",
    "amazon.com",
    "youtube.com",
    "instagram.com",
    "whatsapp.net",
    "live.com",
    "doubleclick.net",
    "bing.com",
    "apple-dns.net",
    "netflix.com",
    "akadns.net",
    "ntp.org",
    "googleusercontent.com",
    "icloud.com",
    "googlesyndication.com",
    "cdninstagram.com",
    "chatgpt.com",
    "cloudflare-dns.com",
    "akamai.net",
    "aaplimg.com",
    "tiktokcdn.com",
    "tiktokv.com",
    "cloudfront.net",
    "ui.com",
    "ytimg.com",
    "akamaiedge.net",
    "edgcdn.net",
    "yahoo.com",
    "gvt2.com",
    "spotify.com",
    "fastly.net",
    "samsung.com",
    "roblox.com",
    "baidu.com",
    "office.com",
    "sentry.io",
    "wikipedia.org",
    "criteo.com",
    "app-analytics-services.com",
    "app-measurement.com",
    "gvt1.com",
    "prodregistryv2.org",
    "steamserver.net",
    "dns.google",
    "one.one",
    "google-analytics.com",
    "msftncsi.com",
    "snapchat.com",
    "applovin.com",
    "3gppnetwork.org",
    "appsflyersdk.com",
    "trafficmanager.net",
    "azure.com",
    "whatsapp.com",
    "googletagmanager.com",
    "windows.com",
    "amazon-adsystem.com",
    "msn.com",
    "googleadservices.com",
    "ggpht.com",
    "oxylabs.io",
    "amazon.dev",
    "linkedin.com",
    "windows.net",
    "unity3d.com",
    "microsoftonline.com",
    "a2z.com",
    "adtrafficquality.google",
    "xiaomi.com",
    "playstation.net",
    "skype.com",
    "rubiconproject.com",
    "capcutapi.com",
    "vungle.com",
    "msftconnecttest.com",
    "taboola.com",
    "windowsupdate.com",
    "digicert.com",
    "gmail.com",
    "cloud.microsoft",
    "qq.com",
    "tiktok.com",
    "aws.dev",
    "miui.com",
    "cdn-apple.com",
    "pubmatic.com",
    "adsrvr.org",
    "avast.com",
    "avsxappcaptiveportal.com",
    "android.com",
    "reddit.com",
]
# ─────────────────────────────────────────────────────────────────────────────
#endregion

#region Helpers
# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_fake_response(ip: str, domain: str) -> bytes:
    """Build a minimal valid DNS A-record response packet."""
    transaction_id = 0x1234
    flags = 0x8180
    header = struct.pack('>HHHHHH', transaction_id, flags, 1, 1, 0, 0)

    question = b''
    for part in domain.split('.'):
        question += struct.pack('B', len(part)) + part.encode()
    question += b'\x00'
    question += struct.pack('>HH', 1, 1)

    answer = (
        struct.pack('>H', 0xC00C) +   # name pointer
        struct.pack('>H', 1) +         # type A
        struct.pack('>H', 1) +         # class IN
        struct.pack('>I', 300) +       # TTL
        struct.pack('>H', 4) +         # rdlength
        bytes(map(int, ip.split('.'))) # rdata
    )

    return header + question + answer
#endregion

#region Test DNSQuery Packet Structure
# ---------------------------------------------------------------------------
# TestCreateDnsQuery — packet structure
# ---------------------------------------------------------------------------

class TestCreateDnsQuery(unittest.TestCase):

    def test_returns_bytes(self):
        self.assertIsInstance(create_dns_query("example.com"), bytes)

    def test_minimum_length(self):
        result = create_dns_query("a.io")
        self.assertGreater(len(result), 12 + 4)

    def test_header_transaction_id(self):
        pkt = create_dns_query("example.com")
        self.assertEqual(struct.unpack('>H', pkt[:2])[0], 0x1234)

    def test_header_flags_standard_query(self):
        pkt = create_dns_query("example.com")
        self.assertEqual(struct.unpack('>H', pkt[2:4])[0], 0x0100)

    def test_header_question_count_is_one(self):
        pkt = create_dns_query("example.com")
        self.assertEqual(struct.unpack('>H', pkt[4:6])[0], 1)

    def test_domain_labels_encoded(self):
        pkt = create_dns_query("example.com")
        self.assertEqual(pkt[12], 7)
        self.assertEqual(pkt[13:20], b'example')

    def test_query_ends_with_null(self):
        pkt = create_dns_query("example.com")
        self.assertIn(b'\x00', pkt[12:])

    def test_query_type_and_class(self):
        pkt = create_dns_query("example.com")
        qtype, qclass = struct.unpack('>HH', pkt[-4:])
        self.assertEqual(qtype, 1)
        self.assertEqual(qclass, 1)
#endregion

#region Test Parser correctness
# ---------------------------------------------------------------------------
# TestParseDnsResponse — parser correctness
# ---------------------------------------------------------------------------

class TestParseDnsResponse(unittest.TestCase):

    def test_returns_valid_ip_string(self):
        fake = build_fake_response("93.184.216.34", "example.com")
        self.assertEqual(parse_dns_response(fake), "93.184.216.34")

    def test_ip_has_four_octets(self):
        fake = build_fake_response("1.2.3.4", "example.com")
        self.assertEqual(len(parse_dns_response(fake).split('.')), 4)

    def test_ip_octets_are_numeric(self):
        fake = build_fake_response("10.0.0.1", "example.com")
        for octet in parse_dns_response(fake).split('.'):
            self.assertTrue(octet.isdigit())

    def test_ip_octets_in_valid_range(self):
        fake = build_fake_response("255.0.128.64", "example.com")
        for octet in parse_dns_response(fake).split('.'):
            self.assertIn(int(octet), range(256))

    def test_returns_none_for_empty_answer(self):
        header = struct.pack('>HHHHHH', 0x1234, 0x8180, 1, 0, 0, 0)
        question = b'\x07example\x03com\x00' + struct.pack('>HH', 1, 1)
        self.assertIsNone(parse_dns_response(header + question))
#endregion

#regiion Test get nameserver
# ---------------------------------------------------------------------------
# TestGetNs — nameserver resolution
# ---------------------------------------------------------------------------

class TestGetNs(unittest.TestCase):

    @patch('src.DNSQuery.dns.resolver.resolve')
    def test_returns_list(self, mock_resolve):
        mock_resolve.return_value = [MagicMock(__str__=lambda s: 'ns1.example.com.')]
        result = get_ns("example.com")
        self.assertIsInstance(result, list)

    @patch('src.DNSQuery.dns.resolver.resolve')
    def test_returns_ns_strings(self, mock_resolve):
        ns_records = ['ns-1372.awsdns-43.org.', 'ns-838.awsdns-40.net.']
        mock_resolve.return_value = [MagicMock(__str__=lambda s, v=v: v) for v in ns_records]
        result = get_ns("netflix.com")
        self.assertEqual(result, ns_records)

    @patch('src.DNSQuery.dns.resolver.resolve')
    def test_no_answer_returns_empty_list(self, mock_resolve):
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NoAnswer
        self.assertEqual(get_ns("example.com"), [])

    @patch('src.DNSQuery.dns.resolver.resolve')
    def test_nxdomain_returns_empty_list(self, mock_resolve):
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        self.assertEqual(get_ns("nonexistent-domain-xyz.com"), [])

    @patch('src.DNSQuery.dns.resolver.resolve')
    def test_ns_records_end_with_dot(self, mock_resolve):
        ns_records = ['ns-1372.awsdns-43.org.', 'ns-1702.awsdns-20.co.uk.']
        mock_resolve.return_value = [MagicMock(__str__=lambda s, v=v: v) for v in ns_records]
        for ns in get_ns("netflix.com"):
            self.assertTrue(ns.endswith('.'), f"NS record '{ns}' should end with a dot")

    @patch('src.DNSQuery.dns.resolver.resolve')
    def test_resolve_called_with_ns_type(self, mock_resolve):
        mock_resolve.return_value = []
        get_ns("example.com")
        mock_resolve.assert_called_once_with("example.com", 'NS')
#endregion

#region SocketTest
# ---------------------------------------------------------------------------
# SocketTest — mocked socket, looped over all DOMAINS
# ---------------------------------------------------------------------------

def make_socket_test(domain: str):

    class SocketTest(unittest.TestCase):

        def _mock_sock(self, ip):
            fake_response = build_fake_response(ip, domain)
            mock_sock = MagicMock()
            mock_sock.recvfrom.return_value = (fake_response, ('8.8.8.8', 53))
            return mock_sock

        @patch('src.DNSQuery.socket.socket')
        def test_returns_string(self, mock_socket_cls):
            mock_socket_cls.return_value = self._mock_sock("93.184.216.34")
            result = dns_query(domain)
            self.assertIsInstance(result, str)

        @patch('src.DNSQuery.socket.socket')
        def test_ip_format(self, mock_socket_cls):
            mock_socket_cls.return_value = self._mock_sock("93.184.216.34")
            result = dns_query(domain)
            parts = result.split('.')
            self.assertEqual(len(parts), 4)
            for p in parts:
                self.assertTrue(p.isdigit())
                self.assertIn(int(p), range(256))

        @patch('src.DNSQuery.socket.socket')
        def test_query_sent_to_correct_server_and_port(self, mock_socket_cls):
            mock_sock = self._mock_sock("1.2.3.4")
            mock_socket_cls.return_value = mock_sock
            dns_query(domain, dns_server='8.8.8.8')
            args = mock_sock.sendto.call_args[0]
            self.assertEqual(args[1], ('8.8.8.8', 53))

        @patch('src.DNSQuery.socket.socket')
        def test_socket_closed_after_query(self, mock_socket_cls):
            mock_sock = self._mock_sock("1.2.3.4")
            mock_socket_cls.return_value = mock_sock
            dns_query(domain)
            mock_sock.close.assert_called_once()

        @patch('src.DNSQuery.socket.socket')
        def test_timeout_returns_none(self, mock_socket_cls):
            mock_sock = MagicMock()
            mock_sock.recvfrom.side_effect = socket.timeout
            mock_socket_cls.return_value = mock_sock
            result = dns_query(domain)
            self.assertIsNone(result)

    SocketTest.__name__ = f"SocketTest_{domain.replace('.', '_').replace('-', '_')}"
    SocketTest.__qualname__ = SocketTest.__name__
    return SocketTest
#endregion

#region extras
for _domain in DOMAINS:
    globals()[f"SocketTest_{_domain.replace('.', '_').replace('-', '_')}"] = make_socket_test(_domain)


if __name__ == '__main__':
    unittest.main(verbosity=2)
#endregion