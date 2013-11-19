from httmock import HTTMock
import requests
import unittest
from webob import exc as wexc

import csr_client
import csr_mock as csr_request


class TestCsrLoginRestApi(unittest.TestCase):
    
    """Test logging into CSR to obtain token-id."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 
                                     'stack', 'cisco')

    def test_get_token(self):
        """Obtain the token and its expiration time."""
        with HTTMock(csr_request.token):
            self.assertTrue(self.csr.login())
        # TODO: Once fixed on CSR, this should return HTTPOk
        self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
        self.assertIsNotNone(self.csr.token)

    def test_unauthorized_token_request(self):
        """Negative test of invalid user/password."""
        self.csr.auth = ('stack', 'bogus')
        with HTTMock(csr_request.token_unauthorized):
            self.assertIsNone(self.csr.login())
        self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)

    def test_non_existent_host(self):
        """Negative test of request to non-existent host."""
        self.csr.host = 'wrong-host'
        self.csr.token = 'Set by some previously successful access'
        with HTTMock(csr_request.token_wrong_host):
            self.assertIsNone(self.csr.login())
        self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
        self.assertIsNone(self.csr.token)

    def test_timeout_on_token_access(self):
        """Negative test of a timeout on a request."""
        with HTTMock(csr_request.token_timeout):
            self.assertIsNone(self.csr.login())
        self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)
        self.assertIsNone(self.csr.token)

class TestCsrGetRestApi(unittest.TestCase):
    
    """Test CSR GET REST API."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 
                                     'stack', 'cisco')

    def test_valid_rest_gets(self):
        """Simple GET requests.
        
        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR."""
        
        with HTTMock(csr_request.token, csr_request.get):
            content = self.csr.get_request('global/host-name')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('host-name', content)
            self.assertNotEqual(None, content['host-name'])
           
            content = self.csr.get_request('global/local-users')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('users', content)

    def test_get_request_for_non_existent_resource(self):
        """Negative test of non-existent resource on get request."""
        with HTTMock(csr_request.token, csr_request.no_such_resource):
            content = self.csr.get_request('no/such/request')
        self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
        self.assertIsNone(content)
                     
    def test_timeout_during_get(self):
        """Negative test of timeout during get resource."""
        with HTTMock(csr_request.token, csr_request.timeout):
            content = self.csr.get_request('global/host-name')
        self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)
        self.assertEqual(None, content)
        
    def test_token_expired_on_get_request(self):
        """Token expired before trying a second get request.

        The mock is configured to return a 401 error on the first
        attempt to reference the host name. For all other get requests
        to for host name and any requests for local users, the proper
        result will be returned."""

        with HTTMock(csr_request.token, csr_request.expired_get,
                     csr_request.get):
            content = self.csr.get_request('global/local-users')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('users', content)
            
            self.csr.token = '123' # These are 44 characters, so won't match
            content = self.csr.get_request('global/host-name')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('host-name', content)
            self.assertNotEqual(None, content['host-name'])

    def test_failed_to_obtain_token_on_get(self):
        """Negative test of unauthorized user for get request."""
        self.csr.auth = ('stack', 'bogus')
        with HTTMock(csr_request.token_unauthorized):
            content = self.csr.get_request('global/host-name')
        self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)
        self.assertIsNone(content)

class TestCsrPostRestApi(unittest.TestCase):
    
    """Test CSR POST REST API."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 
                                     'stack', 'cisco')

    def test_post_requests(self):
        """Simple POST requests (repeatable).
        
        First request will do a post to get token (login). Assumes
        that there are two interfaces (Ge1 and Ge2) on the CSR."""
        
        with HTTMock(csr_request.token, csr_request.post):
            content = self.csr.post_request(
                'interfaces/GigabitEthernet1/statistics',
                payload={'action': 'clear'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
            content = self.csr.post_request(
                'interfaces/GigabitEthernet2/statistics',
                payload={'action': 'clear'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)            
    
    def test_post_invalid_resource(self):
        """Negative test of non-existing resource on post request."""
        with HTTMock(csr_request.token, csr_request.no_such_resource):
            content = self.csr.post_request('no/such/request',
                                            payload={'foo': 'bar'})
        self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
        self.assertIsNone(content)            
    
    def test_timeout_during_post(self):
        """Negative test of timeout during post requests."""
        with HTTMock(csr_request.token, csr_request.timeout):
            content = self.csr.post_request(
                'interfaces/GigabitEthernet1/statistics',
                payload={'action': 'clear'})
        self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)
        self.assertEqual(None, content)
    
    def test_token_expired_on_post_request(self):
        """Negative test of token expired during post request.
        
        Assumes that there are two interfaces (Ge1 and Ge2). First,
        it verifies that we can post to one interface. Next, it
        verifies that a 401 error (unauth) on the first attempt to
        post to the second interface, due to invalid token ID. After
        that, it verifies that posts are successful."""
        with HTTMock(csr_request.token, csr_request.expired_post_put,
                     csr_request.post):
            content = self.csr.post_request(
                'interfaces/GigabitEthernet1/statistics',
                payload={'action': 'clear'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
            
            self.csr.token = '123' # These are 44 characters, so won't match
            content = self.csr.post_request(
                'interfaces/GigabitEthernet2/statistics',
                payload={'action': 'clear'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
    
    def test_failed_to_obtain_token_on_post(self):
        """Negative test of unauthorized user for post request."""
        self.csr.auth = ('stack', 'bogus')
        with HTTMock(csr_request.token_unauthorized):
            content = self.csr.post_request(
                'interfaces/GigabitEthernet1/statistics',
                payload={'action': 'clear'})
        self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)
        self.assertIsNone(content)
    
class TestCsrPutRestApi(unittest.TestCase):
    
    """Test CSR PUT REST API."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 
                                     'stack', 'cisco')

    def _build_payload_from_get(self, details):
        return {u'description': details['description'],
                u'if-name': details['if-name'],
                u'ip-address': details['ip-address'],
                u'subnet-mask': details['subnet-mask'],
                u'type': details['type']}
        
    def test_put_requests(self):
        """Simple PUT requests (repeatable). 
        
        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR (Ge1 and Ge2)."""

        print "PUT test start"
        with HTTMock(csr_request.token, csr_request.put,
                     csr_request.get):
            details = self.csr.get_request('interfaces/GigabitEthernet1')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            print "GET output", details
            payload = self._build_payload_from_get(details)
            payload[u'description'] = "Description changed"
            content = self.csr.put_request('interfaces/GigabitEthernet1',
                                           payload=payload)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
            
            details = self.csr.get_request('interfaces/GigabitEthernet2')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            print "GET output", details
            payload = self._build_payload_from_get(details)
            payload[u'description'] = "Changed another"
            content = self.csr.put_request('interfaces/GigabitEthernet2',
                                           payload=payload)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
    
    def test_put_invalid_resource(self):
        with HTTMock(csr_request.token, csr_request.no_such_resource):
            content = self.csr.put_request('no/such/request',
                                            payload={'foo': 'bar'})
        self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
        self.assertIsNone(content)            
    
    def test_timeout_during_put(self):
        with HTTMock(csr_request.token, csr_request.timeout):
            content = self.csr.put_request(
                'interfaces/GigabitEthernet1',
                payload={'if-name': 'GigabitEthernet1',
                         'description': 'Description changed'})
        self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)
        self.assertEqual(None, content)
    
    def test_token_expired_on_put_request(self):
        """Negative test of token expired during put request.
        
        Assumes that there are two interfaces (Ge1 and Ge2). First,
        it verifies that we can put to one interface. Next, it
        verifies that a 401 error (unauth) on the first attempt to
        put to the second interface, due to invalid token ID. After
        that, it verifies that puts are successful."""
        with HTTMock(csr_request.token, csr_request.expired_post_put,
                     csr_request.put):
            content = self.csr.put_request(
                'interfaces/GigabitEthernet1',
                payload={'if-name': 'GigabitEthernet1',
                         'description': 'Description changed'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
            
            self.csr.token = '123' # These are 44 characters, so won't match
            content = self.csr.put_request(
                'interfaces/GigabitEthernet2',
                payload={'if-name': 'GigabitEthernet1',
                         'description': 'Description changed'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
     
    def test_failed_to_obtain_token_on_put(self):
        """Negative test of unauthorized user for put request."""
        self.csr.auth = ('stack', 'bogus')
        with HTTMock(csr_request.token_unauthorized):
            content = self.csr.put_request(
                'interfaces/GigabitEthernet1',
                payload={'if-name': 'GigabitEthernet1',
                         'description': 'Un-authorized user cannot change'})
        self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)
        self.assertIsNone(content)
     
class TestCsrDeleteRestApi(unittest.TestCase):
    
    """Test CSR DELETE REST API."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 
                                     'stack', 'cisco')

    def test_delete_requests(self):
        """Simple DELETE requests. 
         
        First request will do a post to get token (login). Will do a
        create first, and then delete."""
 
        print "Start DELETE test<<<<<<"
        with HTTMock(csr_request.token, csr_request.post, csr_request.delete):
            content = self.csr.post_request(
                'global/local-users',
                payload={'username': 'dummy',
                         'password': 'dummy',
                         'privilege': 15})
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            content = self.csr.delete_request(
                'global/local-users/dummy')
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)

#     def test_delete_non_existent_entry(self):
#         pass
#     
#     def test_delete_invalid_resource(self):
#         pass
#     
#     def test_timeout_during_delete(self):
#         pass
#     
#     def test_token_expired_on_delete_request(self):
#         pass
#     
#     def test_failed_to_obtain_token_on_delete(self):
#         pass
    

# Functional tests with a real CSR
if True:
    class TestLiveCsrLoginRestApi(TestCsrLoginRestApi):
          
        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20', 
                                         'stack', 'cisco', timeout=2)

    class TestLiveCsrGetRestApi(TestCsrGetRestApi):
          
        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20', 
                                         'stack', 'cisco', timeout=2)

    class TestLiveCsrPostRestApi(TestCsrPostRestApi):
          
        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20', 
                                         'stack', 'cisco', timeout=2)

    class TestLiveCsrPutRestApi(TestCsrPutRestApi):
          
        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20', 
                                         'stack', 'cisco', timeout=2)

    class TestLiveCsrDeleteRestApi(TestCsrDeleteRestApi):
          
        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20', 
                                         'stack', 'cisco', timeout=2)


if __name__ == '__main__':
    unittest.main()

    
