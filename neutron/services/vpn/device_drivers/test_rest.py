# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Paul Michali, Cisco Systems, Inc.

from httmock import HTTMock
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
            self.assertTrue(self.csr.authenticate())
            # TODO(pcm): Once fixed on CSR, this should return HTTPOk
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIsNotNone(self.csr.token)

    def test_unauthorized_token_request(self):
        """Negative test of invalid user/password."""
        self.csr.auth = ('stack', 'bogus')
        with HTTMock(csr_request.token_unauthorized):
            self.assertIsNone(self.csr.authenticate())
            self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)

    def test_non_existent_host(self):
        """Negative test of request to non-existent host."""
        self.csr.host = 'wrong-host'
        self.csr.token = 'Set by some previously successful access'
        with HTTMock(csr_request.token_wrong_host):
            self.assertIsNone(self.csr.authenticate())
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
            self.assertIsNone(self.csr.token)

    def test_timeout_on_token_access(self):
        """Negative test of a timeout on a request."""
        with HTTMock(csr_request.token_timeout):
            self.assertIsNone(self.csr.authenticate())
            self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)
            self.assertIsNone(self.csr.token)


class TestCsrGetRestApi(unittest.TestCase):

    """Test CSR GET REST API."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 'stack', 'cisco')

    def test_valid_rest_gets(self):
        """Simple GET requests.

        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR.
        """

        with HTTMock(csr_request.token, csr_request.get):
            content = self.csr.get_request('global/host-name')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('host-name', content)
            self.assertNotEqual(None, content['host-name'])

            content = self.csr.get_request('global/local-users')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('users', content)


class TestCsrPostRestApi(unittest.TestCase):

    """Test CSR POST REST API."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 'stack', 'cisco')

    def test_post_requests(self):
        """Simple POST requests (repeatable).

        First request will do a post to get token (login). Assumes
        that there are two interfaces (Ge1 and Ge2) on the CSR.
        """

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

class TestCsrPutRestApi(unittest.TestCase):

    """Test CSR PUT REST API."""

    def _save_resources(self):
        with HTTMock(csr_request.token, csr_request.get):
            details = self.csr.get_request('global/host-name')
            if self.csr.status != wexc.HTTPOk.code:
                self.fail("Unable to save original host name")
            self.original_host = details['host-name']
            details = self.csr.get_request('interfaces/GigabitEthernet1')
            if self.csr.status != wexc.HTTPOk.code:
                self.fail("Unable to save interface Ge1 description")
            self.original_desc = details['description']
            self.csr.token = None
            

    def _restore_resources(self, user, password):
        """Restore the host name and itnerface description.

        Must restore the user and password, so that authentication
        token can be obtained (as some tests corrupt auth info).
        Will also clear token, so that it gets a fresh token.
        """

        self.csr.auth = (user, password)
        self.csr.token = None
        with HTTMock(csr_request.token, csr_request.put):
            payload = {'host-name': self.original_host}
            self.csr.put_request('global/host-name', payload=payload)
            if self.csr.status != wexc.HTTPNoContent.code:
                self.fail("Unable to restore host name after test")
            payload = {'description': self.original_desc}
            self.csr.put_request('interfaces/GigabitEthernet1',
                                 payload=payload)
            if self.csr.status != wexc.HTTPNoContent.code:
                self.fail("Unable to restore I/F Ge1 description after test")

    def setUp(self):
        """Prepare for PUT API tests."""
        self.csr = csr_client.Client('localhost', 'stack', 'cisco')
        self._save_resources()
        self.addCleanup(self._restore_resources, 'stack', 'cisco')

    def test_put_requests(self):
        """Simple PUT requests (repeatable).

        First request will do a post to get token (login). Assumes
        that there are two interfaces on the CSR (Ge1 and Ge2).
        """

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

    def test_change_interface_description(self):
        """Test that interface description can be changed.
        
        This was a problem with an earlier version of the CSR image and is
        here to prevent regression.
        """
        with HTTMock(csr_request.token, csr_request.put):
            content = self.csr.put_request(
                'interfaces/GigabitEthernet1',
                payload={'description': 'Changed description'})
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)

class TestCsrDeleteRestApi(unittest.TestCase):

    """Test CSR DELETE REST API."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 'stack', 'cisco')

    def _make_dummy_user(self):
        """Create a user that will be later deleted."""

        self.csr.post_request('global/local-users',
                              payload={'username': 'dummy',
                                       'password': 'dummy',
                                       'privilege': 15})
        self.assertEqual(wexc.HTTPCreated.code, self.csr.status)

    def test_delete_requests(self):
        """Simple DELETE requests (creating entry first)."""
        with HTTMock(csr_request.token, csr_request.post, csr_request.delete):
            self._make_dummy_user()
            self.csr.token = None  # Force login
            self.csr.delete_request('global/local-users/dummy')
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            # Delete again, but without logging in this time
            self._make_dummy_user()
            self.csr.delete_request('global/local-users/dummy')
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)

    def test_delete_non_existent_entry(self):
        """Negative test of trying to delete a non-existent user."""
        with HTTMock(csr_request.token, csr_request.delete_unknown):
            self.csr.delete_request('global/local-users/unknown')
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)

    def test_delete_not_allowed(self):
        """Negative test of trying to delete the host-name."""
        with HTTMock(csr_request.token, csr_request.delete_not_allowed):
            self.csr.delete_request('global/host-name')
            self.assertEqual(wexc.HTTPMethodNotAllowed.code, self.csr.status)


class TestCsrRestApiFailures(unittest.TestCase):

    """Test failure cases common for all REST APIs."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 'stack', 'cisco',
                                     timeout=0.1)

    def test_request_for_non_existent_resource(self):
        """Negative test of non-existent resource on REST request."""
        with HTTMock(csr_request.token, csr_request.no_such_resource):
            content = self.csr._do_request('POST', 'no/such/request')
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
            self.assertIsNone(content)

    def test_timeout_during_request(self):
        """Negative test of timeout during REST request."""
        with HTTMock(csr_request.token, csr_request.timeout):
            content = self.csr._do_request('GET', 'global/host-name')
            self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)
            self.assertEqual(None, content)

    def test_timeout_with_retries_during_request(self):
        """Negative test of retries for timeout during REST request.

        Simulate timeouts four times and then, on fifth request, use
        the normal handler resulting in success.
        """
        with HTTMock(csr_request.token, csr_request.timeout_four_times,
                     csr_request.get):
            content = self.csr._do_request('GET', 'global/local-users')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('users', content)

    def test_token_expired_on_request(self):
        """Token expired before trying a REST request.

        The mock is configured to return a 401 error on the first
        attempt to reference the host name. Simulate expiration of
        token by changing it.
        """

        with HTTMock(csr_request.token, csr_request.expired_request,
                     csr_request.get):
            self.csr.token = '123'  # These are 44 characters, so won't match
            content = self.csr._do_request('GET', 'global/host-name')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('host-name', content)
            self.assertNotEqual(None, content['host-name'])

    def test_failed_to_obtain_token_for_request(self):
        """Negative test of unauthorized user for REST request."""
        self.csr.auth = ('stack', 'bogus')
        with HTTMock(csr_request.token_unauthorized):
            content = self.csr._do_request('GET', 'global/host-name')
            self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)
            self.assertIsNone(content)


# Functional tests with a real CSR
if True:
    class TestLiveCsrLoginRestApi(TestCsrLoginRestApi):

        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=1.0)

    class TestLiveCsrGetRestApi(TestCsrGetRestApi):

        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=1.0)

    class TestLiveCsrPostRestApi(TestCsrPostRestApi):

        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=1.0)

    class TestLiveCsrPutRestApi(TestCsrPutRestApi):

        def setUp(self):
            """Prepare for PUT REST API requests.

            Must save and restore the user and password, as unauthorized
            token test will alter them.

            Note: May need to tune timeout more, as 2 sec seems to trip
            timeout on some test cases.
            """

            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=1.0)
            self._save_resources()
            self.addCleanup(self._restore_resources, 'stack', 'cisco')

    class TestLiveCsrDeleteRestApi(TestCsrDeleteRestApi):

        def _cleanup_user(self):
            """Clean up existing users.

            Invoked before and after tests, so that we can ensure that
            the CSR is in a clean state. Clear the token, so that test
            cases will act as they normally, as if no prior access to
            the CSR.
            """

            with HTTMock(csr_request.token, csr_request.get,
                         csr_request.delete):
                self.csr.get_request('global/local-users/dummy')
                if self.csr.status == wexc.HTTPOk.code:
                    self.csr.delete_request('global/local-users/dummy')
                    if self.csr.status not in (wexc.HTTPNoContent.code,
                                               wexc.HTTPNotFound.code):
                        self.fail("Unable to clean up existing user")
            self.csr.token = None

        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=1.0)
            self._cleanup_user()
            self.addCleanup(self._cleanup_user)

    class TestLiveCsrRestApiFailures(TestCsrRestApiFailures):

        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=1.0)


if __name__ == '__main__':
    unittest.main()
