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
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)
# Enables debug logging to console
if True:
    logging.CONF.set_override('debug', True)
    logging.setup('neutron')


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

    def test_post_with_location(self):
        """Create a user and verify that location returned."""
        with HTTMock(csr_request.token, csr_request.post):
            location = self.csr.post_request(
                'global/local-users',
                payload={'username': 'test-user',
                         'password': 'pass12345',
                         'privilege': 15})
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('global/local-users/test-user', location)

    def test_post_missing_required_attribute(self):
        """Negative test of POST with missing mandatory info."""
        with HTTMock(csr_request.token, csr_request.post):
            location = self.csr.post_request(
                'global/local-users',
                payload={'password': 'pass12345',
                         'privilege': 15})
            self.assertEqual(wexc.HTTPBadRequest.code, self.csr.status)
            self.assertIsNone(location)
        
    def test_post_invalid_attribute(self):
        """Negative test of POST with invalid info."""
        with HTTMock(csr_request.token, csr_request.post):
            location = self.csr.post_request(
                'global/local-users',
                payload={'username': 'test-user',
                         'password': 'pass12345',
                         'privilege': 20})
            self.assertEqual(wexc.HTTPBadRequest.code, self.csr.status)
            self.assertIsNone(location)
        
    def test_post_already_exists(self):
        """Negative test of a duplicate POST."""
        with HTTMock(csr_request.token, csr_request.post_first,
                     csr_request.post_second):
            location = self.csr.post_request(
                'global/local-users',
                payload={'username': 'test-user',
                         'password': 'pass12345',
                         'privilege': 15})
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('global/local-users/test-user', location)
            
            location = self.csr.post_request(
                'global/local-users',
                payload={'username': 'test-user',
                         'password': 'pass12345',
                         'privilege': 15})
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
            self.assertIsNone(location)
        

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
            self.original_if = details
            # TODO(pcm): Remove the next two lines of code, once the bug is
            # fixed, where an empty string is always returned for description.
            if not details.get('description', ''):
                self.original_if['description'] = 'dummy'
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
            payload = {'description': self.original_if['description'],
                       'if-name': self.original_if['if-name'],
                       'ip-address': self.original_if['ip-address'],
                       'subnet-mask': self.original_if['subnet-mask'],
                       'type': self.original_if['type']}
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
        with HTTMock(csr_request.token, csr_request.put, csr_request.get):
            payload = {'description': 'Changed description',
                       'if-name': self.original_if['if-name'],
                       'ip-address': self.original_if['ip-address'],
                       'subnet-mask': self.original_if['subnet-mask'],
                       'type': self.original_if['type']}
            content = self.csr.put_request(
                'interfaces/GigabitEthernet1', payload=payload)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
            content = self.csr.get_request('interfaces/GigabitEthernet1')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('description', content)
            # TODO(pcm): Currently bug in CSR and returns empty string always
            # Uncomment assert, once fixed.
            # self.assertEqual('Changed description', content['description'])

    def ignore_test_change_to_empty_interface_description(self):
        """Test that interface description can be changed to empty string.

        This is a problem in the current version of the CSR image, which
        rejects the change with a 400 error. This test is here to prevent
        a regression (once it is fixed) Note that there is code in the
        test setup to change the description to a non-empty string to
        avoid failures in other tests.
        """
        with HTTMock(csr_request.token, csr_request.put, csr_request.get):
            payload = {'description': '',
                       'if-name': self.original_if['if-name'],
                       'ip-address': self.original_if['ip-address'],
                       'subnet-mask': self.original_if['subnet-mask'],
                       'type': self.original_if['type']}
            content = self.csr.put_request(
                'interfaces/GigabitEthernet1', payload=payload)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.assertIsNone(content)
            content = self.csr.get_request('interfaces/GigabitEthernet1')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            self.assertIn('description', content)
            # TODO(pcm): Uncomment assert, once bug is fixed where the CSR
            # is always returning an empty string.
            # self.assertEqual('', content['description'])


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


class TestCsrRestIkePolicyCreate(unittest.TestCase):

    """Test IKE policy create REST requests."""

    def setUp(self):
        self.csr = csr_client.Client('localhost', 'stack', 'cisco')

    def test_create_ike_policy(self):
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            policy_id = u'2'
            policy_info = {u'priority-id': policy_id,
                           u'encryption': u'aes',
                           u'hash': u'sha',
                           u'dhGroup': 5,
                           u'lifetime': 3600}
            location = self.csr.create_ike_policy(policy_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ike/policies/%s' % policy_id, location)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_policy = {u'kind': u'object#ike-policy',
                               u'version': u'v1',
                               u'local-auth-method': u'pre-share'}
            expected_policy.update(policy_info)
            self.assertEqual(expected_policy, content)

# IPSec....
#             policy_id = '22652e97-5cbb-4598-9590-fafba0576265'
#             policy_info = {
#                 'policy-id': policy_id,
#                 'protection-suite': {
#                     'esp-encryption': 'esp-aes',
#                     'esp-authentication': 'esp-sha-hmac',
#                     'ah': 'ah-sha-hmac',
#                 },
#                 'lifetime-sec': 3600,
#                'pfs': 'group5',
#             }


class TestCsrRestIPSecConnectionCreate(unittest.TestCase):

    """Test IPSec site-to-site connection REST requests."""

    def test_create_ipsec_connection(self):
        """Create an IPSec connection request."""
        pass
#         with HTTMock(csr_request.token, csr_request.post):
#             connection_info = {
#                 'vpn-interface-name': 'tunnel1',
#                 'ipsec-policy-id': "VTI",
#                 'local-device': {'ip-address': '10.3.0.1/30',
#                                  'tunnel-ip-address': '172.24.4.23'},
#                 'remote-device': {'tunnel-ip-address': '172.24.4.11'}
#                 }
#             self.csr.create_ipsec_connection(connection_info)
#             self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)


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

    def _cleanup_user(for_test, name):
        """Clean up existing user.

        Invoked before and after tests, so that we can ensure that
        the CSR is in a clean state. Clear the token, so that test
        cases will act as they would normally, as if no prior access
        to the CSR.
        """

        with HTTMock(csr_request.token, csr_request.delete):
            for_test.csr.delete_request('global/local-users/%s' % name)
            if for_test.csr.status not in (wexc.HTTPNoContent.code,
                                           wexc.HTTPNotFound.code):
                for_test.fail("Unable to clean up existing user '%s'" % name)
        for_test.csr.token = None

    class TestLiveCsrPostRestApi(TestCsrPostRestApi):

        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=1.0)
            _cleanup_user(self, 'test-user')
            self.addCleanup(_cleanup_user, self, 'test-user')

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

        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=1.0)
            _cleanup_user(self, 'dummy')
            self.addCleanup(_cleanup_user, self, 'dummy')

    class TestLiveCsrRestApiFailures(TestCsrRestApiFailures):

        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=1.0)

    class TestLiveCsrRestIkePolicyCreate(TestCsrRestIkePolicyCreate):

        def _ensure_no_existing_policy(self):
            """Ensure no IKE policy exists.

            Invoked before and after tests, so that we can ensure that
            the CSR is in a clean state. Clear the token, so that test
            cases will act as they would normally, as if no prior access
            to the CSR.
            """
            with HTTMock(csr_request.token, csr_request.delete):
                self.csr.delete_request('vpn-svc/ike/policies/2')
                if self.csr.status not in (wexc.HTTPNoContent.code,
                                           wexc.HTTPNotFound.code):
                    self.fail("Unable to clean up existing user")
            self.csr.token = None

        def setUp(self):
            self.csr = csr_client.Client('192.168.200.20',
                                         'stack', 'cisco', timeout=1.0)
            self._ensure_no_existing_policy()
            self.addCleanup(self._ensure_no_existing_policy)


if __name__ == '__main__':
    unittest.main()
