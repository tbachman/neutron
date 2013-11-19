from httmock import HTTMock
import requests
import unittest
from webob import exc as wexc

import csr_client
import csr_mock as csr_request


class TestCsrLoginRestApi(unittest.TestCase):
    
    """Test logging into CSR to obtain token-id."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 'stack', 'cisco')

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
        self.csr = csr_client.Client('localhost', 'stack', 'cisco')

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
        attempt to reference the host name. Simulate expiration of
        token by changing it."""

        with HTTMock(csr_request.token, csr_request.expired_get,
                     csr_request.get):
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
        self.csr = csr_client.Client('localhost', 'stack', 'cisco')

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
        
        Simulates expiration of the token by changing it."""
        with HTTMock(csr_request.token, csr_request.expired_post_put,
                     csr_request.post):
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
                'interfaces/GigabitEthernet1/statistics',
                payload={'action': 'clear'})
        self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)
        self.assertIsNone(content)

    
class TestCsrPutRestApi(unittest.TestCase):
    
    """Test CSR PUT REST API."""

    def _save_host_name(self):
        with HTTMock(csr_request.token, csr_request.get):
            details = self.csr.get_request('global/host-name')
            if self.csr.status != wexc.HTTPOk.code:
                self.fail("Unable to save original host name")
        self.original_host = details['host-name']
        self.csr.token = None

    def _restore_host_name(self):
        """Restore the host name.
        
        Must restore the user and password, so that authentication
        token can be obtained (as some tests corrupt auth info)."""
        
        self.csr.auth = ('stack', 'cisco')
        with HTTMock(csr_request.token, csr_request.put):
            payload = {'host-name': self.original_host}
            self.csr.put_request('global/host-name', payload=payload)
            if self.csr.status != wexc.HTTPNoContent.code:
                self.fail("Unable to restore host name after test")

    def setUp(self):
        """Prepare for PUT API tests."""
        self.csr = csr_client.Client('localhost', 'stack', 'cisco')
        self._save_host_name()
        
    def tearDown(self):
        self._restore_host_name()

    def test_put_requests(self):
        """Simple PUT requests (repeatable). 
        
        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR (Ge1 and Ge2)."""

        with HTTMock(csr_request.token, csr_request.put,
                     csr_request.get):
            payload = {'host-name': 'TestHost'}
            content = self.csr.put_request('global/host-name',
                                           payload=payload)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
            
            payload = {'host-name': 'TestHost2'}
            content = self.csr.put_request('global/host-name',
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
            payload = {'host-name': 'TimeoutHost'}
            content = self.csr.put_request('global/host-name',
                                           payload=payload)
        self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)
        self.assertEqual(None, content)
    
    def test_token_expired_on_put_request(self):
        """Negative test of token expired during put request.
        
        Will alter the token to simulate expiration, requiring
        re-login. Expect it to be successful after getting new
        token."""
        with HTTMock(csr_request.token, csr_request.expired_post_put,
                     csr_request.put):
            self.csr.token = '123' # These are 44 characters, so won't match
            payload = {'host-name': 'TestHost2'}
            content = self.csr.put_request('global/host-name',
                                           payload=payload)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
     
    def test_failed_to_obtain_token_on_put(self):
        """Negative test of unauthorized user for put request.
        
        We need to change the password, so that the login fails for the
        test case."""
        self.csr.auth = ('stack', 'bogus')
        with HTTMock(csr_request.token_unauthorized):
            payload = {'host-name': 'TestHost'}
            content = self.csr.put_request('global/host-name',
                                           payload=payload)
        self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)
        self.assertIsNone(content)


class TestCsrDeleteRestApi(unittest.TestCase):
    
    """Test CSR DELETE REST API."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 'stack', 'cisco')

    def test_delete_requests(self):
        """Simple DELETE requests. 
         
        First request will do a post to get token (login). Will do a
        create first, and then delete."""
 
        with HTTMock(csr_request.token, csr_request.post, csr_request.delete):
            content = self.csr.post_request('global/local-users',
                                            payload={'username': 'dummy',
                                                     'password': 'dummy',
                                                     'privilege': 15})
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            content = self.csr.delete_request(
                'global/local-users/dummy')
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)

    def test_delete_non_existent_entry(self):
        """Negative test of trying to delete a non-existent user."""
        with HTTMock(csr_request.token, csr_request.delete_unknown):
           content = self.csr.delete_request('global/local-users/unknown')
           self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)

     
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
            """Prepare for PUT REST API requests.
            
            Must save and restore the user and password, as unauthorized
            token test will alter them."""
    
            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=2)
            self._save_host_name()
            
        def tearDown(self):
            self._restore_host_name()
            
    class TestLiveCsrDeleteRestApi(TestCsrDeleteRestApi):
          
        def _cleanup_users(self):
            """Clean up existing users.
            
            Invoked before and after tests, so that we can ensure that
            the CSR is in a clean state. Clear the token, so that test
            cases will act as they normally, as if no prior access to
            the CSR."""
            with HTTMock(csr_request.token, csr_request.get, csr_request.delete):
                details = self.csr.get_request('global/local-users/dummy')
                if self.csr.status == wexc.HTTPOk.code:
                    self.csr.delete_request('global/local-users/dummy')
                    if self.csr.status not in (wexc.HTTPNoContent.code,
                                               wexc.HTTPNotFound.code):
                        self.fail("Unable to clean up existing user")
            self.csr.token = None
    
        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20', 
                                         'stack', 'cisco', timeout=2)
            self._cleanup_users()
            
        def tearDown(self):
            self._cleanup_users()
                

if __name__ == '__main__':
    unittest.main()

    
