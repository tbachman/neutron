from httmock import HTTMock
import requests
import unittest
from webob import exc as wexc

import csr_client
import csr_mock as csr_request


class TestCsrRestApi(unittest.TestCase):

    def setUp(self):
        self.csr = csr_client.Client('localhost', 
                                     'stack', 'cisco')

    #############################################
    # Tests of access token
    #############################################
    def test_get_token(self):
        """Obtain the token and its expiration time."""
        with HTTMock(csr_request.token):
            self.assertTrue(self.csr.login())
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

    #############################################
    # Tests of REST GET
    #############################################
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

    #############################################
    # Tests of REST POST
    #############################################
    def test_post_requests(self):
        """Simple POST requests (repeatable).
        
        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR."""
        
        with HTTMock(csr_request.token, csr_request.post):
            content = self.csr.post_request(
                'interfaces/GigabitEthernet0/statistics',
                payload={'action': 'clear'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
            content = self.csr.post_request(
                'interfaces/GigabitEthernet1/statistics',
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
                'interfaces/GigabitEthernet0/statistics',
                payload={'action': 'clear'})
        self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)
        self.assertEqual(None, content)
    
    def test_token_expired_on_post_request(self):
        """Negative test of token expired during post request.
        
        The mock is configured to return a 401 error on the first
        attempt to reference statistics for GigabitEthernet1. For
        all other post requests to this and GigabitEthernet0, the
        proper result will be returned."""
        with HTTMock(csr_request.token, csr_request.expired_post,
                     csr_request.post):
            content = self.csr.post_request(
                'interfaces/GigabitEthernet0/statistics',
                payload={'action': 'clear'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
            
            self.csr.token = '123' # These are 44 characters, so won't match
            content = self.csr.post_request(
                'interfaces/GigabitEthernet1/statistics',
                payload={'action': 'clear'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
    
    def test_failed_to_obtain_token_on_post(self):
        """Negative test of unauthorized user for post request."""
        self.csr.auth = ('stack', 'bogus')
        with HTTMock(csr_request.token_unauthorized):
            content = self.csr.post_request(
                'interfaces/GigabitEthernet0/statistics',
                payload={'action': 'clear'})
        self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)
        self.assertIsNone(content)
    
    #############################################
    # Tests of REST PUT
    #############################################
    def test_put_requests(self):
        """Simple PUT requests (repeatable). 
        
        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR."""

        with HTTMock(csr_request.token, csr_request.put):
            content = self.csr.put_request(
                'interfaces/GigabitEthernet0',
                payload={'description': 'Description changed'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
            content = self.csr.put_request(
                'interfaces/GigabitEthernet1',
                payload={'description': 'Description changed'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
    
    def test_put_invalid_resource(self):
        pass
    
    def test_timeout_during_put(self):
        pass
    
    def test_token_expired_on_put_request(self):
        pass
    
    def test_failed_to_obtain_token_on_post(self):
        pass
    
    #############################################
    # Tests of REST DELETE
    #############################################
    def test_delete_requests(self):
        pass
    
    def test_delete_invalid_resource(self):
        pass
    
    def test_timeout_during_delete(self):
        pass
    
    def test_token_expired_on_delete_request(self):
        pass
    
    def test_failed_to_obtain_token_on_delete(self):
        pass
    

# Functional tests with a real CSR
if True:
    class TestLiveCsr(TestCsrRestApi):
          
        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20', 
                                         'stack', 'cisco', timeout=2)

if __name__ == '__main__':
    unittest.main()

    
