# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013, Nachi Ueno, NTT I3, Inc.
# All Rights Reserved.
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

import mock

from neutron import context
from neutron.services.vpn import service_drivers
from neutron.tests.unit.services.vpn.service_drivers import test_ipsec


class TestGenericVPNRpcDriver(test_ipsec.TestIPsecDriver):
    def setUp(self):
        super(TestGenericVPNRpcDriver, self).setUp()
        self.driver = service_drivers.GenericVPNRpcDriver(self.service_plugin)

    def _test_update(self, func, args, method_name=''):
        ctxt = context.Context('', 'somebody')
        with mock.patch.object(self.driver.agent_rpc, 'cast') as cast:
            kwargs = {}
            if len(args) > 1:
                kwargs['old_resource'] = args[0]
                kwargs['resource'] = args[1]
            else:
                kwargs['resource'] = args[0]
            func(ctxt, *args)
            cast.assert_called_once_with(
                ctxt,
                {'args': kwargs,
                 'namespace': None,
                 'method': method_name},
                topic='vpn_rpc_fake_provider')

    def test_call_undefied_method(self):
        ctxt = context.Context('', 'somebody')
        self.assertRaises(AttributeError, self.driver.undef_func, ctxt)
