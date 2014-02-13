# Copyright (c) 2014 Cisco Systems
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
#
# @author: Henry Gessau, Cisco Systems

import mock

from neutron.common import log
from neutron import context
from neutron.extensions import flavor
from neutron.plugins.cisco.l3 import l3_apic
from neutron.plugins.common import constants
from neutron.plugins.ml2.drivers.cisco.apic import apic_manager as am
from neutron.tests import base
from neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as mocked)


LOG = log.logging.getLogger(__name__)


class TestCiscoApicL3Service(base.BaseTestCase,
                             mocked.ControllerMixin,
                             mocked.ConfigMixin,
                             mocked.DbModelMixin):

    def setUp(self):
        super(TestCiscoApicL3Service, self).setUp()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        mocked.DbModelMixin.set_up_mocks(self)

        self.mock_apic_manager_login_responses()
        self.l3svc = l3_apic.ApicL3ServicePlugin()
        self.session = self.l3svc.manager.apic.session
        self.assert_responses_drained()
        self.reset_reponses()

        self.context = context.get_admin_context()

        self.addCleanup(mock.patch.stopall)

    def test_get_plugin_type(self):
        plugin = self.l3svc.get_plugin_type()
        self.assertEqual(plugin, constants.L3_ROUTER_NAT)

    def test_get_plugin_description(self):
        description = self.l3svc.get_plugin_description()
        self.assertGreater(len(description), 0)

    def test_add_router_interface(self):
        router = self._fake_router('apic_flavor')
        interface = {'subnet_id': self._fake_subnet(mocked.APIC_SUBNET)}
        with mock.patch.object(am, 'APICManager') as apic_mgr:
            # TODO(Henry): work in progress
            # self.l3svc.add_router_interface(self.context, router, interface)
            if apic_mgr:
                LOG.debug('WIP %s %s %s', self.context, router, interface)
            pass

    def _fake_subnet(self, net_id):
        allocation_pools = [{'start': '10.0.0.2',
                             'end': '10.0.0.254'}]
        return {'subnet': {'name': net_id,
                           'network_id': net_id,
                           'gateway_ip': '10.0.0.1',
                           'dns_nameservers': ['10.0.0.2'],
                           'host_routes': [],
                           'cidr': '10.0.0.0/24',
                           'allocation_pools': allocation_pools,
                           'enable_dhcp': True,
                           'ip_version': 4}}

    def _fake_router(self, router_flavor):
        return {'router': {'name': router_flavor, 'admin_state_up': True,
                           'tenant_id': mocked.APIC_TENANT,
                           flavor.FLAVOR_ROUTER: router_flavor,
                           'external_gateway_info': None}}
