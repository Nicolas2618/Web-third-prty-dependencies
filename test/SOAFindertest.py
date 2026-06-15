import unittest
from unittest.mock import patch, MagicMock

from src.SOAFinder import classify_ns, get_tld


def make_mock_whois(org=None, name=None, registrar=None):
    obj = MagicMock()
    obj.org = org
    obj.name = name
    obj.registrar = registrar
    return obj


class TestSOAFinderWhois(unittest.TestCase):

    @patch('src.SOAFinder.whois.whois')
    def test_amazonaws_ns_matches_whois_with_raw_ns_fallback(self, mock_whois):
        domain = 'amazonaws.com'
        ns = 'ns-1670.awsdns-16.co.uk'
        domain_tld = get_tld(domain)

        mock_whois.side_effect = [
            make_mock_whois(org='Amazon.com, Inc.', name='Legal Department', registrar='MarkMonitor, Inc.'),
            make_mock_whois(org=None, name=None, registrar='Markmonitor Inc. [Tag = MARKMONITOR]'),
        ]

        ns_type, reason = classify_ns(ns, domain, domain_tld, False, set(), None)
        self.assertEqual(ns_type, 'private')
        self.assertEqual(reason, 'same organization in whois')


if __name__ == '__main__':
    unittest.main(verbosity=2)
