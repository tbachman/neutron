from httmock import urlmatch, all_requests, HTTMock
import requests
from webob import exc as wexc

import csr_client
import unittest


# Helper functions to mock REST requests
@urlmatch(netloc=r'localhost')
def csr_token_mock(url, request):
    if 'auth/token-services' in url.path:
        return {'status_code': wexc.HTTPCreated.code,
                'content': {'token-id': 'dummy-token'}}

@urlmatch(netloc=r'localhost')
def csr_token_unauthorized_mock(url, request):
    if 'auth/token-services' in url.path:
        return {'status_code': wexc.HTTPUnauthorized.code}

@urlmatch(netloc=r'wrong-host')
def csr_token_wrong_host_mock(url, request):
    raise requests.ConnectionError()
    
@all_requests
def csr_timeout_mock(url, request):
    raise requests.Timeout()

@urlmatch(netloc=r'localhost')
def csr_request_not_found_mock(url, request):
    if 'no/such/request' in url.path:
        return {'status_code': wexc.HTTPNotFound.code,
                'content': {'token-id': 'dummy-token'}}

@urlmatch(netloc=r'localhost')
def csr_get_mock(url, request):
    if 'global/host-name' in url.path:
        return {'status_code': wexc.HTTPOk.code,
                'content': {u'kind': u'object#host-name',
                            u'host-name': u'Router'}}
    if 'global/local-users' in url.path:
        return {'status_code': wexc.HTTPOk.code,
                'content': {u'kind': u'collection#local-user', 
                            u'users': ['peter', 'paul', 'mary']}}

def repeat(n):
    """Decorator to limit the number of times a handler is called.
    
    HTTMock mocks calls to the requests libary, by using one or more
    "handlers" that are registered. The first handler is tried, and
    if it returns None (instead of a dict), the next handler is tried,
    until a dict is returned, or no more handlers exist. To allow
    different responses for a single resource, we can use this decorator
    to limit the number of times a handler will respond (returning None,
    when the limit is reached), thereby allowing other handlers to try
    to respond."""
    
    class static:
        times = n
    def decorator(func):
        def wrapped(*args, **kwargs):
            if static.times == 0:
                return None
            static.times -= 1
            return func(*args, **kwargs)
        return wrapped
    return decorator

@repeat(1)
@urlmatch(netloc=r'localhost')
def csr_expired_get_mock(url, request):
    if 'global/host-name' in url.path:
        return {'status_code': wexc.HTTPOk.code,
                'content': {u'kind': u'object#host-name',
                            u'host-name': u'Router'}}


class TestCsrRestApi(unittest.TestCase):

    def setUp(self):
        self.csr = csr_client.Client('localhost', 
                                     'stack', 'cisco')

    # Tests of access token
    def test_get_token(self):
        """Obtain the token and its expiration time."""
        with HTTMock(csr_token_mock):
            self.assertTrue(self.csr.obtain_access_token())
        self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
        self.assertIsNotNone(self.csr.token)

    def test_unauthorized_token_request(self):
        """Negative test of invalid user/password."""
        self.csr.auth = ('stack', 'bogus')
        with HTTMock(csr_token_unauthorized_mock):
            self.assertIsNone(self.csr.obtain_access_token())
        self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)

    def test_non_existent_host(self):
        """Negative test of request to non-existent host."""
        self.csr.host = 'wrong-host'
        self.csr.token = 'Set by some previously successful access'
        with HTTMock(csr_token_wrong_host_mock):
            self.assertIsNone(self.csr.obtain_access_token())
        self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
        self.assertIsNone(self.csr.token)

    def test_timeout_on_token_access(self):
        """Negative test of a timeout on a request."""
        with HTTMock(csr_timeout_mock):
            self.assertIsNone(self.csr.obtain_access_token())
        self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)
        self.assertIsNone(self.csr.token)

    # Tests of REST GET
    def test_valid_rest_gets(self):
        """First request will get token."""
        with HTTMock(csr_token_mock, csr_get_mock):
            content = self.csr.get_request('global/host-name')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('host-name', content)
            self.assertNotEqual(None, content['host-name'])
            # May not want to do following, as actual router may be different
            self.assertDictContainsSubset({'host-name': 'Router'}, content)
            
            # Already have token for this request
            content = self.csr.get_request('global/local-users')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('users', content)

    def test_get_request_for_non_existent_resource(self):
        """Negative test of non-existent resource."""
        with HTTMock(csr_token_mock, csr_request_not_found_mock):
            content = self.csr.get_request('no/such/request')
        self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
        self.assertIsNone(content)
                     
    def test_timeout_during_get(self):
        """Negative test of timeout during get resource."""
        with HTTMock(csr_token_mock, csr_timeout_mock):
            content = self.csr.get_request('global/host-name')
        self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)
        self.assertEqual(None, content)
        
    def test_token_expired_on_get_request(self):
        """Token expired before trying a second get request."""
        with HTTMock(csr_token_mock, csr_expired_get_mock, csr_get_mock):
            content = self.csr.get_request('global/host-name')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.csr.token = '123' # These are 44 characters, so won't match
            content = self.csr.get_request('global/host-name')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('host-name', content)
            self.assertNotEqual(None, content['host-name'])

    def test_failed_to_obtain_token_on_get(self):
        """Negative test of timeout obtaining token for get request."""
        self.csr.auth = ('stack', 'bogus')
        with HTTMock(csr_token_unauthorized_mock):
            content = self.csr.get_request('global/host-name')
        self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)
        self.assertIsNone(content)
   

class TestLiveCsr(TestCsrRestApi):
      
    def setUp(self):
        self.csr = csr_client.Client('192.168.200.20', 
                                     'stack', 'cisco', timeout=2)

if __name__ == '__main__':
    unittest.main()

    
