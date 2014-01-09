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

import cisco_csr_mock as csr_request
import cisco_csr_rest_client as csr_client
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)
# Enables debug logging to console
if True:
    logging.CONF.set_override('debug', True)
    logging.setup('neutron')


class TestCsrLoginRestApi(unittest.TestCase):

    """Test logging into CSR to obtain token-id."""

    def setUp(self):
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')

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
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')

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
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')

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
            self.csr.post_request('global/local-users',
                                  payload={'password': 'pass12345',
                                           'privilege': 15})
            self.assertEqual(wexc.HTTPBadRequest.code, self.csr.status)

    def test_post_invalid_attribute(self):
        """Negative test of POST with invalid info."""
        with HTTMock(csr_request.token, csr_request.post):
            self.csr.post_request('global/local-users',
                                  payload={'username': 'test-user',
                                           'password': 'pass12345',
                                           'privilege': 20})
            self.assertEqual(wexc.HTTPBadRequest.code, self.csr.status)

    def test_post_already_exists(self):
        """Negative test of a duplicate POST.

        Uses the lower level _do_request() API to just perform the POST and
        obtain the response, without any error processing.
        """
        with HTTMock(csr_request.token, csr_request.post):
                location = self.csr._do_request(
                    'POST',
                    'global/local-users',
                    payload={'username': 'test-user',
                             'password': 'pass12345',
                             'privilege': 15},
                    more_headers=csr_client.HEADER_CONTENT_TYPE_JSON)
                self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
                self.assertIn('global/local-users/test-user', location)
        with HTTMock(csr_request.token, csr_request.post_duplicate):
                self.csr._do_request(
                    'POST',
                    'global/local-users',
                    payload={'username': 'test-user',
                             'password': 'pass12345',
                             'privilege': 15},
                    more_headers=csr_client.HEADER_CONTENT_TYPE_JSON)
                # TODO(pcm): Uncomment, once CSR fixes response status
                # self.assertEqual(wexc.HTTPBadRequest.code, self.csr.status)

    def test_post_changing_value(self):
        """Negative test of a POST trying to change a value."""
        with HTTMock(csr_request.token, csr_request.post):
            location = self.csr.post_request(
                'global/local-users',
                payload={'username': 'test-user',
                         'password': 'pass12345',
                         'privilege': 15})
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('global/local-users/test-user', location)
        with HTTMock(csr_request.token, csr_request.post_change_attempt):
            content = self.csr.post_request('global/local-users',
                                            payload={'username': 'test-user',
                                                     'password': 'changed',
                                                     'privilege': 15})
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
            expected = {u'error-code': -1,
                        u'error-message': u'user test-user already exists'}
            self.assertDictContainsSubset(expected, content)


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
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')
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
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')

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
            content = self.csr.delete_request('global/local-users/unknown')
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
            expected = {u'error-code': -1,
                        u'error-message': u'user unknown not found'}
            self.assertDictContainsSubset(expected, content)

    def test_delete_not_allowed(self):
        """Negative test of trying to delete the host-name."""
        with HTTMock(csr_request.token, csr_request.delete_not_allowed):
            self.csr.delete_request('global/host-name')
            self.assertEqual(wexc.HTTPMethodNotAllowed.code, self.csr.status)


class TestCsrRestApiFailures(unittest.TestCase):

    """Test failure cases common for all REST APIs.

    Uses the lower level _do_request() to just perform the operation and get
    the result, without any error handling.
    """

    def setUp(self):
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco',
                                            timeout=0.1)

    def test_request_for_non_existent_resource(self):
        """Negative test of non-existent resource on REST request."""
        with HTTMock(csr_request.token, csr_request.no_such_resource):
            self.csr.post_request('no/such/request')
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)
            # The result is HTTP 404 message, so no error content to check

    def test_timeout_during_request(self):
        """Negative test of timeout during REST request."""
        with HTTMock(csr_request.token, csr_request.timeout):
            self.csr._do_request('GET', 'global/host-name')
            self.assertEqual(wexc.HTTPRequestTimeout.code, self.csr.status)

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
            self.csr._do_request('GET', 'global/host-name')
            self.assertEqual(wexc.HTTPUnauthorized.code, self.csr.status)


class TestCsrRestIkePolicyCreate(unittest.TestCase):

    """Test IKE policy create REST requests."""

    def setUp(self):
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')

    def test_create_delete_ike_policy(self):
        """Create and then delete IKE policy."""
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            policy_id = '2'
            policy_info = {u'priority-id': u'%s' % policy_id,
                           u'encryption': u'aes',
                           u'hash': u'sha',
                           u'dhGroup': 5,
                           u'lifetime': 3600}
            location = self.csr.create_ike_policy(policy_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ike/policies/%s' % policy_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_policy = {u'kind': u'object#ike-policy',
                               u'version': u'v1',
                               u'local-auth-method': u'pre-share'}
            expected_policy.update(policy_info)
            self.assertEqual(expected_policy, content)
        # Now delete and verify the IKE policy is gone
        with HTTMock(csr_request.token, csr_request.delete,
                     csr_request.no_such_resource):
            self.csr.delete_ike_policy(policy_id)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)

    def test_create_ike_policy_with_defaults(self):
        """Create IKE policy using defaults for all optional values."""
        with HTTMock(csr_request.token, csr_request.post,
                     csr_request.get_defaults):
            policy_id = '2'
            policy_info = {u'priority-id': u'%s' % policy_id}
            location = self.csr.create_ike_policy(policy_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ike/policies/%s' % policy_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_policy = {u'kind': u'object#ike-policy',
                               u'version': u'v1',
                               u'encryption': u'des',
                               u'hash': u'sha',
                               u'dhGroup': 1,
                               u'lifetime': 86400,
                               # Lower level sets this, but it is the default
                               u'local-auth-method': u'pre-share'}
            expected_policy.update(policy_info)
            self.assertEqual(expected_policy, content)

    def test_create_duplicate_ike_policy(self):
        """Negative test of trying to create a dulicate IKE policy."""
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            policy_id = '2'
            policy_info = {u'priority-id': u'%s' % policy_id,
                           u'encryption': u'aes',
                           u'hash': u'sha',
                           u'dhGroup': 5,
                           u'lifetime': 3600}
            location = self.csr.create_ike_policy(policy_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ike/policies/%s' % policy_id, location)
        with HTTMock(csr_request.token, csr_request.post_duplicate):
            location = self.csr.create_ike_policy(policy_info)
            self.assertEqual(wexc.HTTPBadRequest.code, self.csr.status)
            expected = {u'error-code': -1,
                        u'error-message': u'policy 2 exist, not allow to '
                        u'update policy using POST method'}
            self.assertDictContainsSubset(expected, location)


class TestCsrRestIPSecPolicyCreate(unittest.TestCase):

    """Test IPSec policy create REST requests."""

    def setUp(self):
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')

    def test_create_delete_ipsec_policy(self):
        """Create and then delete IPSec policy."""
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            policy_id = '123'
            policy_info = {
                u'policy-id': u'%s' % policy_id,
                u'protection-suite': {
                    u'esp-encryption': u'esp-aes',
                    u'esp-authentication': u'esp-sha-hmac',
                    u'ah': u'ah-sha-hmac',
                },
                u'lifetime-sec': 120,
                u'pfs': u'group5',
                # TODO(pcm): Remove when CSR fixes 'Disable'
                u'anti-replay-window-size': u'128'
            }
            location = self.csr.create_ipsec_policy(policy_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ipsec/policies/%s' % policy_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_policy = {u'kind': u'object#ipsec-policy',
                               u'mode': u'tunnel',
                               # TODO(pcm): Uncomment, when fixed on CSR
                               # u'anti-replay-window-size': 'Disable',
                               u'lifetime-kb': None,
                               u'idle-time': None}
            expected_policy.update(policy_info)
            self.assertEqual(expected_policy, content)
        # Now delete and verify the IPSec policy is gone
        with HTTMock(csr_request.token, csr_request.delete,
                     csr_request.no_such_resource):
            self.csr.delete_ipsec_policy(policy_id)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)

    def test_create_ipsec_policy_with_defaults(self):
        """Create IPSec policy with default for all optional values."""
        with HTTMock(csr_request.token, csr_request.post,
                     csr_request.get_defaults):
            policy_id = '123'
            policy_info = {
                u'policy-id': u'%s' % policy_id,
                # Override, as we normally force this to 'Disable'
                u'anti-replay-window-size': u'64',
            }
            location = self.csr.create_ipsec_policy(policy_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ipsec/policies/%s' % policy_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_policy = {u'kind': u'object#ipsec-policy',
                               u'policy-id': policy_id,
                               u'mode': u'tunnel',
                               u'protection-suite': {},
                               u'lifetime-sec': None,
                               u'pfs': u'Disable',
                               u'anti-replay-window-size': u'64',
                               u'lifetime-kb': None,
                               u'idle-time': None}
            self.assertEqual(expected_policy, content)

    def test_create_ipsec_policy_with_uuid(self):
        """Create IPSec policy using UUID for id."""
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            policy_info = {
                u'policy-id': u'%s' % csr_request.dummy_uuid,
                u'protection-suite': {
                    u'esp-encryption': u'esp-aes',
                    u'esp-authentication': u'esp-sha-hmac',
                    u'ah': u'ah-sha-hmac',
                },
                u'lifetime-sec': 120,
                u'pfs': u'group5',
                # TODO(pcm): Remove when CSR fixes 'Disable'
                u'anti-replay-window-size': u'128'
            }
            location = self.csr.create_ipsec_policy(policy_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ipsec/policies/%s' % csr_request.dummy_uuid,
                          location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_policy = {u'kind': u'object#ipsec-policy',
                               u'mode': u'tunnel',
                               # TODO(pcm): Uncomment, when fixed on CSR
                               # u'anti-replay-window-size': 'Disable',
                               u'lifetime-kb': None,
                               u'idle-time': None}
            expected_policy.update(policy_info)
            self.assertEqual(expected_policy, content)

    def test_create_ipsec_policy_without_ah(self):
        """Create IPSec policy."""
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            policy_id = '10'
            policy_info = {
                u'policy-id': u'%s' % policy_id,
                u'protection-suite': {
                    u'esp-encryption': u'esp-aes',
                    u'esp-authentication': u'esp-sha-hmac',
                },
                u'lifetime-sec': 120,
                u'pfs': u'group5',
                # TODO(pcm): Remove when CSR fixes 'Disable'
                u'anti-replay-window-size': u'128'
            }
            location = self.csr.create_ipsec_policy(policy_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ipsec/policies/%s' % policy_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_policy = {u'kind': u'object#ipsec-policy',
                               u'mode': u'tunnel',
                               # TODO(pcm): Uncomment, when fixed on CSR
                               # u'anti-replay-window-size': 'Disable',
                               u'lifetime-kb': None,
                               u'idle-time': None}
            expected_policy.update(policy_info)
            self.assertEqual(expected_policy, content)


class TestCsrRestPreSharedKeyCreate(unittest.TestCase):

    """Test Pre-shared key (PSK) create REST requests."""

    def setUp(self):
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')

    def test_create_delete_pre_shared_key(self):
        """Create and then delete a keyring entry for pre-shared key."""
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            psk_id = '5'
            psk_info = {u'keyring-name': u'%s' % psk_id,
                        u'pre-shared-key-list': [
                            {u'key': u'super-secret',
                             u'encrypted': False,
                             u'peer-address': u'10.10.10.20/24'}
                        ]}
            location = self.csr.create_pre_shared_key(psk_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ike/keyrings/%s' % psk_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_policy = {u'kind': u'object#ike-keyring'}
            expected_policy.update(psk_info)
            # Note: the peer CIDR is returned as an IP and mask
            expected_policy[u'pre-shared-key-list'][0][u'peer-address'] = (
                u'10.10.10.20 255.255.255.0')
            self.assertEqual(expected_policy, content)
        # Now delete and verify pre-shared key is gone
        with HTTMock(csr_request.token, csr_request.delete,
                     csr_request.no_such_resource):
            self.csr.delete_pre_shared_key(psk_id)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)

    def test_create_pre_shared_key_with_fqdn_peer(self):
        """Create pre-shared key using FQDN for peer address."""
        with HTTMock(csr_request.token, csr_request.post,
                     csr_request.get_fqdn):
            psk_id = '5'
            psk_info = {u'keyring-name': u'%s' % psk_id,
                        u'pre-shared-key-list': [
                            {u'key': u'super-secret',
                             u'encrypted': False,
                             u'peer-address': u'cisco.com'}
                        ]}
            location = self.csr.create_pre_shared_key(psk_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ike/keyrings/%s' % psk_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_policy = {u'kind': u'object#ike-keyring'}
            expected_policy.update(psk_info)
            self.assertEqual(expected_policy, content)

    def test_create_pre_shared_key_with_duplicate_peer_address(self):
        """Negative test of creating a second pre-shared key with same peer."""
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            psk_id = '5'
            psk_info = {u'keyring-name': u'%s' % psk_id,
                        u'pre-shared-key-list': [
                            {u'key': u'super-secret',
                             u'encrypted': False,
                             u'peer-address': u'10.10.10.20/24'}
                        ]}
            location = self.csr.create_pre_shared_key(psk_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/ike/keyrings/%s' % psk_id, location)
        with HTTMock(csr_request.token, csr_request.post_duplicate):
            psk_id = u'6'
            another_psk_info = {u'keyring-name': psk_id,
                                u'pre-shared-key-list': [
                                    {u'key': u'abc123def',
                                     u'encrypted': False,
                                     u'peer-address': u'10.10.10.20/24'}
                                ]}
            self.csr.create_ike_policy(another_psk_info)
            self.assertEqual(wexc.HTTPBadRequest.code, self.csr.status)


class TestCsrRestIPSecConnectionCreate(unittest.TestCase):

    """Test IPSec site-to-site connection REST requests.

    This requires us to have first created an IKE policy, IPSec policy,
    and pre-shared key, so it's more of an itegration test, when used
    with a real CSR (as we can't mock out these pre-conditions.
    """

    def setUp(self):
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')

    def _make_ike_policy_for_test(self):
        with HTTMock(csr_request.token, csr_request.post):
            policy_id = u'2'
            policy_info = {u'priority-id': policy_id,
                           u'encryption': u'aes',
                           u'hash': u'sha',
                           u'dhGroup': 5,
                           u'lifetime': 3600}
            self.csr.create_ike_policy(policy_info)
            if self.csr.status != wexc.HTTPCreated.code:
                self.fail("Unable to create IKE policy for test case")

    def _make_psk_for_test(self):
        with HTTMock(csr_request.token, csr_request.post):
            psk_info = {u'keyring-name': u'5',
                        u'pre-shared-key-list': [
                            {u'key': u'super-secret',
                             u'encrypted': False,
                             u'peer-address': u'10.10.10.20/24'}
                        ]}
            self.csr.create_pre_shared_key(psk_info)
            if self.csr.status != wexc.HTTPCreated.code:
                self.fail("Unable to create PSK for test case")

    def _make_ipsec_policy_for_test(self):
        with HTTMock(csr_request.token, csr_request.post):
            policy_info = {
                u'policy-id': u'123',
                u'protection-suite': {
                    u'esp-encryption': u'esp-aes',
                    u'esp-authentication': u'esp-sha-hmac',
                    u'ah': u'ah-sha-hmac',
                },
                u'lifetime-sec': 120,
                u'pfs': u'group5',
                u'anti-replay-window-size': u'64'
            }
            self.csr.create_ipsec_policy(policy_info)
            if self.csr.status != wexc.HTTPCreated.code:
                self.fail("Unable to create IPSec policy for test case")

    def test_create_delete_ipsec_connection(self):
        """Create and then delete an IPSec connection."""
        # Setup needed items for test
        self._make_ike_policy_for_test()
        self._make_psk_for_test()
        self._make_ipsec_policy_for_test()
        tunnel_id = 'Tunnel0'
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            connection_info = {
                u'vpn-interface-name': u'%s' % tunnel_id,
                u'ipsec-policy-id': u'123',
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            location = self.csr.create_ipsec_connection(connection_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/site-to-site/%s' % tunnel_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_connection = {u'kind': u'object#vpn-site-to-site',
                                   u'ip-version': u'ipv4'}
            expected_connection.update(connection_info)
            self.assertEqual(expected_connection, content)
        # Now delete and verify that site-to-site connection is gone
        with HTTMock(csr_request.token, csr_request.delete,
                     csr_request.no_such_resource):
            # Only delete connection. Cleanup will take care of prerequisites
            self.csr.delete_ipsec_connection(tunnel_id)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)

    def test_create_ipsec_connection_no_pre_shared_key(self):
        """Test of connection create without associated pre-shared key.

        The CSR will create the connection, but will not be able to pass
        traffic without the pre-shared key.
        """
        self._make_ike_policy_for_test()
        self._make_ipsec_policy_for_test()
        tunnel_id = 'Tunnel0'
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            connection_info = {
                u'vpn-interface-name': u'%s' % tunnel_id,
                u'ipsec-policy-id': u'123',
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': '10.10.10.20'}
            }
            location = self.csr.create_ipsec_connection(connection_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('vpn-svc/site-to-site/%s' % tunnel_id, location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_connection = {u'kind': u'object#vpn-site-to-site',
                                   u'ip-version': u'ipv4'}
            expected_connection.update(connection_info)
            self.assertEqual(expected_connection, content)

    def test_create_ipsec_connection_missing_ike_policy(self):
        """Test of connection create without IKE policy (uses default).

        Without an IKE policy, the CSR will use a built-in default IKE
        policy setting for the connection.
        """
        self._make_psk_for_test()
        self._make_ipsec_policy_for_test()
        tunnel_id = 'Tunnel0'
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            connection_info = {
                u'vpn-interface-name': u'%s' % tunnel_id,
                u'ipsec-policy-id': u'123',
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': '10.10.10.20'}
            }
            location = self.csr.create_ipsec_connection(connection_info)
            self.assertIn('vpn-svc/site-to-site/%s' % tunnel_id, location)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_connection = {u'kind': u'object#vpn-site-to-site',
                                   u'ip-version': u'ipv4'}
            expected_connection.update(connection_info)
            self.assertEqual(expected_connection, content)

    def test_create_ipsec_connection_missing_ipsec_policy(self):
        """Negative test of connection create without IPSec policy."""
        self._make_ike_policy_for_test()
        self._make_psk_for_test()
        tunnel_id = 'Tunnel0'
        with HTTMock(csr_request.token, csr_request.post_missing_ipsec_policy):
            connection_info = {
                u'vpn-interface-name': u'%s' % tunnel_id,
                u'ipsec-policy-id': u'NoSuchPolicy',
                u'local-device': {u'ip-address': u'10.3.0.1/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': '10.10.10.20'}
            }
            self.csr.create_ipsec_connection(connection_info)
            self.assertEqual(wexc.HTTPBadRequest.code, self.csr.status)

    def test_create_ipsec_connection_conficting_tunnel_ip(self):
        """Negative test of connection create with conflicting tunnel IP.

        The GigabitEthernet3 interface has an IP of 10.2.0.6. This will
        try a connection create with an IP that is on the same subnet.
        """

        # Setup needed items for test
        self._make_ike_policy_for_test()
        self._make_psk_for_test()
        self._make_ipsec_policy_for_test()
        tunnel_id = 'Tunnel0'
        with HTTMock(csr_request.token, csr_request.post_bad_ip):
            connection_info = {
                u'vpn-interface-name': u'%s' % tunnel_id,
                u'ipsec-policy-id': u'123',
                u'local-device': {u'ip-address': u'10.2.0.10/24',
                                  u'tunnel-ip-address': u'10.10.10.10'},
                u'remote-device': {u'tunnel-ip-address': u'10.10.10.20'}
            }
            self.csr.create_ipsec_connection(connection_info)
            # TODO(pcm): This should be a 400 error - waiting for fix.
            self.assertEqual(wexc.HTTPInternalServerError.code,
                             self.csr.status)


class TestCsrRestIkeKeepaliveCreate(unittest.TestCase):

    """Test IKE keepalive REST requests.

    This is a global configuration that will apply to all VPN tunnels and
    is used to specify Dead Peer Detection information. Currently, the API
    supports DELETE API, but a bug has been created to remove the API and
    add an indicator of when the capability is disabled.

    TODO(pcm): revise tests  to not delete, but change to disabled, once
    the CSR is updated.
    """

    def setUp(self):
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')

    def test_configure_ike_keepalive(self):
        """Set IKE keep-alive (aka Dead Peer Detection) for the CSR."""
        with HTTMock(csr_request.token, csr_request.put, csr_request.get):
            keepalive_info = {'interval': 60, 'retry': 4}
            self.csr.configure_ike_keepalive(keepalive_info)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            content = self.csr.get_request('vpn-svc/ike/keepalive')
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected = {'periodic': False}
            expected.update(keepalive_info)
            self.assertDictContainsSubset(expected, content)

    def test_disable_ike_keepalive(self):
        """Disable IKE keep-alive (aka Dead Peer Detection) for the CSR."""
        with HTTMock(csr_request.token, csr_request.delete, csr_request.put,
                     csr_request.get_not_configured):
            # TODO(pcm): When CSR is updated, comment out and update the
            # following code to do the disable. Remove the delete mock, above.
#             keepalive_info = {'interval': 0, 'retry': 4}
#             self.csr.configure_ike_keepalive(keepalive_info)
#             self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            self.csr.delete_request('vnc-svc/ike/keepalive')
            self.assertIn(self.csr.status,
                          (wexc.HTTPNoContent.code, wexc.HTTPNotFound.code))
            self.csr.get_request('vpn-svc/ike/keepalive')
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)


class TestCsrRestStaticRoute(unittest.TestCase):

    """Test static route REST requests.

    A static route is added for the peer's private network. Would create
    a route for each of the peer CIDRs specified for the VPN connection.
    """

    def setUp(self):
        self.csr = csr_client.CsrRestClient('localhost', 'stack', 'cisco')

    def test_create_delete_static_route(self):
        """Create and then delete a static route for the tunnel."""
        cidr = u'10.1.0.0/24'
        interface = u'GigabitEthernet1'
        expected_id = '10.1.0.0_24_GigabitEthernet1'
        with HTTMock(csr_request.token, csr_request.post, csr_request.get):
            route_info = {u'destination-network': cidr,
                          u'outgoing-interface': interface}
            location = self.csr.create_static_route(route_info)
            self.assertEqual(wexc.HTTPCreated.code, self.csr.status)
            self.assertIn('routing-svc/static-routes/%s' % expected_id,
                          location)
            # Check the hard-coded items that get set as well...
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPOk.code, self.csr.status)
            expected_route = {u'kind': u'object#static-route',
                              u'next-hop-router': None,
                              u'admin-distance': 1}
            expected_route.update(route_info)
            self.assertEqual(expected_route, content)
        # Now delete and verify that static route is gone
        with HTTMock(csr_request.token, csr_request.delete,
                     csr_request.no_such_resource):
            route_id = self.csr.make_route_id(cidr, interface)
            self.csr.delete_static_route(route_id)
            self.assertEqual(wexc.HTTPNoContent.code, self.csr.status)
            content = self.csr.get_request(location, full_url=True)
            self.assertEqual(wexc.HTTPNotFound.code, self.csr.status)

# Functional tests with a real CSR
if True:
    def _cleanup_resource(for_test, resource):
        """Ensure that the specified resource does not exist.

        Invoked before and after tests, so that we can ensure that
        the CSR is in a clean state. The caller should clear the token
        after cleaning up the last resource, so that test cases will
        act as they would normally, as if no prior access to the CSR.
        """

        with HTTMock(csr_request.token, csr_request.delete):
            for_test.csr.delete_request(resource)
            if for_test.csr.status not in (wexc.HTTPNoContent.code,
                                           wexc.HTTPNotFound.code):
                for_test.fail("Unable to clean up resource '%s'" % resource)

    class TestLiveCsrLoginRestApi(TestCsrLoginRestApi):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)

    class TestLiveCsrGetRestApi(TestCsrGetRestApi):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)

    class TestLiveCsrPostRestApi(TestCsrPostRestApi):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)
            _cleanup_resource(self, 'global/local-users/test-user')
            self.csr.token = None
            self.addCleanup(_cleanup_resource, self,
                            'global/local-users/test-user')

    class TestLiveCsrPutRestApi(TestCsrPutRestApi):

        def setUp(self):
            """Prepare for PUT REST API requests.

            Must save and restore the user and password, as unauthorized
            token test will alter them.

            Note: May need to tune timeout more, as 2 sec seems to trip
            timeout on some test cases.
            """

            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)
            self._save_resources()
            self.csr.token = None
            self.addCleanup(self._restore_resources, 'stack', 'cisco')

    class TestLiveCsrDeleteRestApi(TestCsrDeleteRestApi):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)
            _cleanup_resource(self, 'global/local-users/dummy')
            self.csr.token = None
            self.addCleanup(_cleanup_resource, self,
                            'global/local-users/dummy')

    class TestLiveCsrRestApiFailures(TestCsrRestApiFailures):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)

    class TestLiveCsrRestIkePolicyCreate(TestCsrRestIkePolicyCreate):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)
            self.csr.delete_ike_policy('2')
            self.csr.token = None
            self.addCleanup(self.csr.delete_ike_policy, '2')

    class TestLiveCsrRestPreSharedKeyCreate(TestCsrRestPreSharedKeyCreate):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)
            self.csr.delete_pre_shared_key('5')
            self.csr.token = None
            self.addCleanup(self.csr.delete_pre_shared_key, '5')

    class TestLiveCsrRestIPSecPolicyCreate(TestCsrRestIPSecPolicyCreate):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)
            self.csr.delete_ipsec_policy('123')
            self.csr.delete_ipsec_policy(csr_request.dummy_uuid)
            self.csr.delete_ipsec_policy('10')
            self.csr.token = None
            self.addCleanup(self.csr.delete_ipsec_policy, '123')
            self.addCleanup(self.csr.delete_ipsec_policy,
                            csr_request.dummy_uuid)
            self.addCleanup(self.csr.delete_ipsec_policy, '10')

    class TestLiveCsrRestIPSecConnectionCreate(
            TestCsrRestIPSecConnectionCreate):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)
            self.csr.delete_ipsec_connection('Tunnel0')
            self.csr.delete_pre_shared_key('5')
            self.csr.delete_ipsec_policy('123')
            self.csr.delete_ike_policy('2')
            self.csr.token = None
            # These will be deleted in reverse order, which is required, as
            # you cannot delete the IPSec policy, when in use by a tunnel.
            self.addCleanup(self.csr.delete_ike_policy, '2')
            self.addCleanup(self.csr.delete_ipsec_policy, '123')
            self.addCleanup(self.csr.delete_pre_shared_key, '5')
            self.addCleanup(self.csr.delete_ipsec_connection, 'Tunnel0')

    class TestLiveCsrRestIkeKeepaliveCreate(TestCsrRestIkeKeepaliveCreate):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)
            # TODO(pcm): Remvoe, once CSR changes API to remove delete. Will
            # then need to do a put with a 'disabled' indication.
            _cleanup_resource(self, 'vpn-svc/ike/policy')
            self.csr.token = None
            self.addCleanup(_cleanup_resource, self, 'vpn-svc/ike/keepalive')

    class TestLiveCsrRestStaticRoute(TestCsrRestStaticRoute):

        def setUp(self):
            self.csr = csr_client.CsrRestClient('192.168.200.20',
                                                'stack', 'cisco',
                                                timeout=csr_client.TIMEOUT)
            route_id = self.csr.make_route_id('10.1.0.0/24',
                                              'GigabitEthernet1')
            self.csr.delete_static_route(route_id)
            self.csr.token = None
            self.addCleanup(self.csr.delete_static_route, route_id)

if __name__ == '__main__':
    unittest.main()
