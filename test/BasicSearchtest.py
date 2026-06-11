import unittest
from unittest.mock import patch, MagicMock
import dns.resolver
from src.BasicSearch import get_ns, get_ns_lst

# ── Domains mirroring get_ns_lst ─────────────────────────────────────────────
DOMAINS = [
    "google.com", "github.com", "googleapis.com", "cloudflare.com", "gstatic.com",
    "apple.com", "microsoft.com", "facebook.com", "amazonaws.com", "googlevideo.com",
    "fbcdn.net", "amazon.com", "youtube.com", "instagram.com", "whatsapp.net",
    "live.com", "doubleclick.net", "bing.com", "apple-dns.net", "netflix.com",
    "akadns.net", "ntp.org", "googleusercontent.com", "icloud.com", "googlesyndication.com",
    "cdninstagram.com", "chatgpt.com", "cloudflare-dns.com", "akamai.net", "aaplimg.com",
    "tiktokcdn.com", "tiktokv.com", "cloudfront.net", "ui.com", "ytimg.com",
    "akamaiedge.net", "edgcdn.net", "yahoo.com", "gvt2.com", "spotify.com",
    "fastly.net", "samsung.com", "roblox.com", "baidu.com", "office.com",
    "sentry.io", "wikipedia.org", "criteo.com", "app-analytics-services.com",
    "app-measurement.com", "gvt1.com", "prodregistryv2.org", "steamserver.net",
    "dns.google", "one.one", "google-analytics.com", "msftncsi.com", "snapchat.com",
    "applovin.com", "3gppnetwork.org", "appsflyersdk.com", "trafficmanager.net",
    "azure.com", "whatsapp.com", "googletagmanager.com", "windows.com",
    "amazon-adsystem.com", "msn.com", "googleadservices.com", "ggpht.com",
    "oxylabs.io", "amazon.dev", "linkedin.com", "windows.net", "unity3d.com",
    "microsoftonline.com", "a2z.com", "adtrafficquality.google", "xiaomi.com",
    "playstation.net", "skype.com", "rubiconproject.com", "capcutapi.com",
    "vungle.com", "msftconnecttest.com", "taboola.com", "windowsupdate.com",
    "digicert.com", "gmail.com", "cloud.microsoft", "qq.com", "tiktok.com",
    "aws.dev", "miui.com", "cdn-apple.com", "pubmatic.com", "adsrvr.org",
    "avast.com", "avsxappcaptiveportal.com", "android.com", "reddit.com",
]
# ─────────────────────────────────────────────────────────────────────────────


def make_mock_ns(records: list[str]):
    """Build a list of mock rdata objects that str() to the given record strings."""
    return [MagicMock(__str__=lambda s, v=v: v) for v in records]


# ---------------------------------------------------------------------------
# TestGetNs — unit tests for get_ns()
# ---------------------------------------------------------------------------

class TestGetNs(unittest.TestCase):

    @patch('src.BasicSearch.dns.resolver.resolve')
    def test_returns_list(self, mock_resolve):
        mock_resolve.return_value = make_mock_ns(['ns1.example.com.'])
        self.assertIsInstance(get_ns("example.com"), list)

    @patch('src.BasicSearch.dns.resolver.resolve')
    def test_returns_correct_ns_strings(self, mock_resolve):
        ns = ['ns-1372.awsdns-43.org.', 'ns-838.awsdns-40.net.']
        mock_resolve.return_value = make_mock_ns(ns)
        self.assertEqual(get_ns("netflix.com"), ns)

    @patch('src.BasicSearch.dns.resolver.resolve')
    def test_no_answer_returns_empty_list(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NoAnswer
        self.assertEqual(get_ns("example.com"), [])

    @patch('src.BasicSearch.dns.resolver.resolve')
    def test_nxdomain_returns_empty_list(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        self.assertEqual(get_ns("nonexistent-xyz.com"), [])

    @patch('src.BasicSearch.dns.resolver.resolve')
    def test_called_with_ns_type(self, mock_resolve):
        mock_resolve.return_value = []
        get_ns("example.com")
        mock_resolve.assert_called_once_with("example.com", 'NS')

    @patch('src.BasicSearch.dns.resolver.resolve')
    def test_multiple_ns_records_all_returned(self, mock_resolve):
        ns = ['ns1.example.com.', 'ns2.example.com.', 'ns3.example.com.', 'ns4.example.com.']
        mock_resolve.return_value = make_mock_ns(ns)
        result = get_ns("example.com")
        self.assertEqual(len(result), 4)

    @patch('src.BasicSearch.dns.resolver.resolve')
    def test_each_record_is_string(self, mock_resolve):
        mock_resolve.return_value = make_mock_ns(['ns1.example.com.', 'ns2.example.com.'])
        for record in get_ns("example.com"):
            self.assertIsInstance(record, str)


# ---------------------------------------------------------------------------
# TestGetNsLst — unit tests for get_ns_lst()
# ---------------------------------------------------------------------------

class TestGetNsLst(unittest.TestCase):

    @patch('src.BasicSearch.get_ns')
    def test_returns_dict(self, mock_get_ns):
        mock_get_ns.return_value = ['ns1.example.com.']
        self.assertIsInstance(get_ns_lst(), dict)

    @patch('src.BasicSearch.get_ns')
    def test_all_domains_present_as_keys(self, mock_get_ns):
        mock_get_ns.return_value = ['ns1.example.com.']
        result = get_ns_lst()
        for domain in DOMAINS:
            self.assertIn(domain, result, msg=f"'{domain}' missing from result dict")

    @patch('src.BasicSearch.get_ns')
    def test_values_are_lists(self, mock_get_ns):
        mock_get_ns.return_value = ['ns1.example.com.']
        result = get_ns_lst()
        for domain, ns_list in result.items():
            self.assertIsInstance(ns_list, list, msg=f"Value for '{domain}' should be a list")

    @patch('src.BasicSearch.get_ns')
    def test_get_ns_called_once_per_domain(self, mock_get_ns):
        mock_get_ns.return_value = []
        get_ns_lst()
        self.assertEqual(mock_get_ns.call_count, len(DOMAINS))

    @patch('src.BasicSearch.get_ns')
    def test_empty_ns_stored_correctly(self, mock_get_ns):
        mock_get_ns.return_value = []
        result = get_ns_lst()
        for domain in DOMAINS:
            self.assertEqual(result[domain], [])

    @patch('src.BasicSearch.get_ns')
    def test_ns_records_stored_per_domain(self, mock_get_ns):
        # Each domain gets a unique NS record so we can verify correct mapping
        mock_get_ns.side_effect = lambda d: [f'ns1.{d}.']
        result = get_ns_lst()
        for domain in DOMAINS:
            self.assertEqual(result[domain], [f'ns1.{domain}.'])

    @patch('src.BasicSearch.get_ns')
    def test_result_key_count_matches_domain_list(self, mock_get_ns):
        mock_get_ns.return_value = ['ns1.example.com.']
        result = get_ns_lst()
        self.assertEqual(len(result), len(DOMAINS))


# ---------------------------------------------------------------------------
# Per-domain tests — looped over all DOMAINS
# ---------------------------------------------------------------------------

def make_domain_test(domain: str):

    class DomainTest(unittest.TestCase):

        @patch('src.BasicSearch.dns.resolver.resolve')
        def test_result_is_list(self, mock_resolve):
            mock_resolve.return_value = make_mock_ns(['ns1.test.com.'])
            self.assertIsInstance(get_ns(domain), list)

        @patch('src.BasicSearch.dns.resolver.resolve')
        def test_no_answer_gives_empty_list(self, mock_resolve):
            mock_resolve.side_effect = dns.resolver.NoAnswer
            self.assertEqual(get_ns(domain), [])

        @patch('src.BasicSearch.dns.resolver.resolve')
        def test_nxdomain_gives_empty_list(self, mock_resolve):
            mock_resolve.side_effect = dns.resolver.NXDOMAIN
            self.assertEqual(get_ns(domain), [])

        @patch('src.BasicSearch.dns.resolver.resolve')
        def test_records_are_strings(self, mock_resolve):
            mock_resolve.return_value = make_mock_ns(['ns1.test.com.', 'ns2.test.com.'])
            for record in get_ns(domain):
                self.assertIsInstance(record, str)

    DomainTest.__name__ = f"DomainTest_{domain.replace('.', '_').replace('-', '_')}"
    DomainTest.__qualname__ = DomainTest.__name__
    return DomainTest


for _domain in DOMAINS:
    globals()[f"DomainTest_{_domain.replace('.', '_').replace('-', '_')}"] = make_domain_test(_domain)


if __name__ == '__main__':
    unittest.main(verbosity=2)