#import unittest
#from unittest.mock import patch, MagicMock
#
#from src.SOAFinder import classify_ns, get_tld
#
#
#def make_mock_whois(org=None, name=None, registrar=None):
#    obj = MagicMock()
#    obj.org = org
#    obj.name = name
#    obj.registrar = registrar
#    return obj
#
#
#class TestSOAFinderWhois(unittest.TestCase):
#
#    @patch('src.SOAFinder.whois.whois')
#    def test_amazonaws_ns_matches_whois_with_raw_ns_fallback(self, mock_whois):
#        domain = 'amazonaws.com'
#        ns = 'ns-1670.awsdns-16.co.uk'
#        domain_tld = get_tld(domain)
#
#        mock_whois.side_effect = [
#            make_mock_whois(org='Amazon.com, Inc.', name='Legal Department', registrar='MarkMonitor, Inc.'),
#            make_mock_whois(org=None, name=None, registrar='Markmonitor Inc. [Tag = MARKMONITOR]'),
#        ]
#
#        ns_type, reason = classify_ns(ns, domain, domain_tld, False, set(), None)
#        self.assertEqual(ns_type, 'private')
#        self.assertEqual(reason, 'same organization in whois')
#
#    @patch('src.SOAFinder.whois.whois')
#    @patch('src.SOAFinder.get_auth_ns_set')
#    @patch('src.SOAFinder.builtwith_dns_provider_match')
#    def test_domain_connected_to_nameserver_provider_via_builtwith(
#        self, mock_builtwith_match, mock_get_auth_ns_set, mock_whois):
#        domain = 'example.com'
#        ns = 'ns1.cloudflare.com'
#        domain_tld = get_tld(domain)
#
#        mock_builtwith_match.return_value = True
#        mock_get_auth_ns_set.side_effect = [
#            {'ns1.example.com'},
#            {'ns2.cloudflare.com'},
#        ]
#        mock_whois.return_value = make_mock_whois(org=None, name=None, registrar=None)
#
#        ns_type, reason = classify_ns(ns, domain, domain_tld, False, set(), None)
#        self.assertEqual(ns_type, 'private')
#        self.assertIn('BuiltWith', reason)
#        self.assertIn('nameserver provider', reason)
#
#
#if __name__ == '__main__':
#    unittest.main(verbosity=2)
#