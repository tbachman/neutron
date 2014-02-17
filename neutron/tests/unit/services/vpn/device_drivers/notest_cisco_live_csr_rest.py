# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import httplib
import unittest

from neutron.services.vpn.device_drivers import (
    cisco_csr_rest_client as csr_client)
from neutron.tests.unit.services.vpn.device_drivers import (
    cisco_csr_mock as csr_request)
from neutron.tests.unit.services.vpn.device_drivers import (
    test_cisco_csr_rest as test_csr)


# TODO(pcm) Since these work with a live CSR (hardcoded right now), don't run
# as part of TOX. Could be used for Tempest third party testing. Also, update
# to read CSR info from config file.


def _cleanup_resource(for_test, resource):
    """Ensure that the specified resource does not exist.

    Invoked before and after tests, so that we can ensure that
    the CSR is in a clean state. The caller should clear the token
    after cleaning up the last resource, so that test cases will
    act as they would normally, as if no prior access to the CSR.
    """

    for_test.csr.delete_request(resource)
    if for_test.csr.status not in (httplib.NO_CONTENT,
                                   httplib.NOT_FOUND):
        for_test.fail("Unable to clean up resource '%s'" % resource)


class TestLiveCsrLoginRestApi(test_csr.TestCsrLoginRestApi):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)


class TestLiveCsrGetRestApi(test_csr.TestCsrGetRestApi):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)


class TestLiveCsrPostRestApi(test_csr.TestCsrPostRestApi):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)
        _cleanup_resource(self, 'global/local-users/test-user')
        self.csr.token = None
        self.addCleanup(_cleanup_resource, self,
                        'global/local-users/test-user')


class TestLiveCsrPutRestApi(test_csr.TestCsrPutRestApi):

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


class TestLiveCsrDeleteRestApi(test_csr.TestCsrDeleteRestApi):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)
        _cleanup_resource(self, 'global/local-users/dummy')
        self.csr.token = None
        self.addCleanup(_cleanup_resource, self,
                        'global/local-users/dummy')


class TestLiveCsrRestApiFailures(test_csr.TestCsrRestApiFailures):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)


class TestLiveCsrRestIkePolicyCreate(test_csr.TestCsrRestIkePolicyCreate):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)
        self.csr.delete_ike_policy('2')
        self.csr.token = None
        self.addCleanup(self.csr.delete_ike_policy, '2')


class TestLiveCsrRestPreSharedKeyCreate(
        test_csr.TestCsrRestPreSharedKeyCreate):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)
        self.csr.delete_pre_shared_key('5')
        self.csr.token = None
        self.addCleanup(self.csr.delete_pre_shared_key, '5')


class TestLiveCsrRestIPSecPolicyCreate(test_csr.TestCsrRestIPSecPolicyCreate):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)
        self.csr.delete_ipsec_policy('123')
        self.csr.delete_ipsec_policy(test_csr.dummy_uuid)
        self.csr.delete_ipsec_policy('10')
        self.csr.token = None
        self.addCleanup(self.csr.delete_ipsec_policy, '123')
        self.addCleanup(self.csr.delete_ipsec_policy, test_csr.dummy_uuid)
        self.addCleanup(self.csr.delete_ipsec_policy, '10')


class TestLiveCsrRestIPSecConnectionCreate(
        test_csr.TestCsrRestIPSecConnectionCreate):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)


class TestLiveCsrRestIkeKeepaliveCreate(
        test_csr.TestCsrRestIkeKeepaliveCreate):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)
        if csr_request.FIXED_CSCum10324:
            self.fail("Need to get current setting to later restore "
                      "and setup cleanup to restore")
        else:
            _cleanup_resource(self, 'vpn-svc/ike/policy')
            self.addCleanup(_cleanup_resource, self,
                            'vpn-svc/ike/keepalive')
        self.csr.token = None


class TestLiveCsrRestStaticRoute(test_csr.TestCsrRestStaticRoute):

    def setUp(self):
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)
        route_id = csr_client.make_route_id('10.1.0.0/24',
                                            'GigabitEthernet1')
        self.csr.delete_static_route(route_id)
        self.csr.token = None
        self.addCleanup(self.csr.delete_static_route, route_id)


if __name__ == '__main__':
    unittest.main()
