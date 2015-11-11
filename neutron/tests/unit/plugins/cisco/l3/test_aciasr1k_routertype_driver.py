# Copyright 2015 Cisco Systems, Inc.  All rights reserved.
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

import contextlib

import mock
from oslo_config import cfg

from neutron import context
from neutron.api.v2 import attributes
from neutron.common import constants as l3_constants
from neutron.extensions import l3
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.db.l3 import ha_db
from neutron.plugins.cisco.extensions import ha
from neutron.plugins.cisco.extensions import routerhostingdevice
from neutron.plugins.cisco.extensions import routerrole
from neutron.plugins.cisco.extensions import routertype
from neutron.plugins.cisco.extensions import routertypeawarescheduler
from neutron.tests.unit.plugins.cisco.l3 import (
    test_ha_l3_router_appliance_plugin as cisco_ha_test)
from neutron.tests.unit.plugins.cisco.l3 import (
    test_l3_routertype_aware_schedulers as cisco_test_case)
from neutron.tests.unit.plugins.cisco.l3 import (
    test_asr1k_routertype_driver as asr1k)
from neutron.plugins.cisco.l3.drivers.asr1k import (
    aci_asr1k_routertype_driver as aciasr1k)
import webob.exc

_uuid = uuidutils.generate_uuid

EXTERNAL_GW_INFO = l3.EXTERNAL_GW_INFO
AGENT_TYPE_L3_CFG = cisco_constants.AGENT_TYPE_L3_CFG
ROUTER_ROLE_GLOBAL = cisco_constants.ROUTER_ROLE_GLOBAL
ROUTER_ROLE_LOGICAL_GLOBAL = cisco_constants.ROUTER_ROLE_LOGICAL_GLOBAL
ROUTER_ROLE_HA_REDUNDANCY = cisco_constants.ROUTER_ROLE_HA_REDUNDANCY
LOGICAL_ROUTER_ROLE_NAME = cisco_constants.LOGICAL_ROUTER_ROLE_NAME
ROUTER_ROLE_ATTR = routerrole.ROUTER_ROLE_ATTR
HOSTING_DEVICE_ATTR = routerhostingdevice.HOSTING_DEVICE_ATTR
AUTO_SCHEDULE_ATTR = routertypeawarescheduler.AUTO_SCHEDULE_ATTR


class AciASR1kL3RouterDriverWrapper(aciasr1k.AciASR1kL3RouterDriver):
    """Wrapper class for testing.

    This class modifies the base class so that the lower level
    driver calls are mocked or stubbed, in order to facilitate
    testing.
    """
    def __init__(self):
        super(AciASR1kL3RouterDriverWrapper, self).__init__()

        self.driver_mock = mock.MagicMock()
        self.ml2_mock = mock.MagicMock()
        self.manager = mock.MagicMock()
        self.name_mapper = mock.MagicMock()

    @property
    def ml2_plugin(self):
        return self.ml2_mock

    @property
    def aci_mech_driver(self):
        return self.driver_mock

    def update_port_status(self, context, id, status):
        pass


class AciAsr1kRouterTypeDriverTestCase(
        asr1k.Asr1kRouterTypeDriverTestCase):

    router_type = 'ASR1k_Neutron_router'

    def _create_req(self, resource, data, id,
                    expected_code=webob.exc.HTTPOk.code,
                    fmt=None, subresource=None, neutron_context=None):
        req = self.new_update_request(resource, data, id,
                                      fmt=fmt,
                                      subresource=subresource)
        if neutron_context:
            # create a specific auth context for this request
            req.environ['neutron.context'] = neutron_context
        res = req.get_response(self._api_for_resource(resource))
        self.assertEqual(res.status_int, expected_code)
        return self.deserialize(self.fmt, res)

    def _test_gw_router_create_add_interface(self, set_context=False):
        tenant_id = _uuid()
        with self.network(tenant_id=tenant_id) as n_external:
            res = self._create_subnet(self.fmt, n_external['network']['id'],
                                      cidr='10.0.1.0/24', tenant_id=tenant_id)
            s = self.deserialize(self.fmt, res)
            self._set_net_external(s['subnet']['network_id'])
            ext_gw = {'network_id': s['subnet']['network_id']}
            with self.router(tenant_id=tenant_id, external_gateway_info=ext_gw,
                             set_context=set_context) as router1:
                r1 = router1['router']
                self.plugin._process_backlogged_routers()
                r1_after = self._show('routers', r1['id'])['router']
                hd_id = r1_after[HOSTING_DEVICE_ATTR]
                # should have one global router now
                self._verify_created_routers({r1['id']}, hd_id)
                with self.network(tenant_id=tenant_id) as n_internal:
                    res = self._create_subnet(self.fmt, n_internal['network']['id'],
                                              cidr='20.0.1.0/24', tenant_id=tenant_id)
                    s_int = self.deserialize(self.fmt, res)
                    self._set_net_external(s_int['subnet']['network_id'])
                    port = {'port': {'name': 'port',
                                     'network_id': s_int['subnet']['network_id'],
                                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                                     'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                                     'admin_state_up': True,
                                     #'device_id': r1_after['id'],
                                     'device_id': '',
                                     #'device_owner': l3_constants.DEVICE_OWNER_ROUTER_INTF,
                                     'device_owner': '',
                                     'tenant_id': s['subnet']['tenant_id']}}
                    ctx = context.Context('', '', is_admin=True)
                    port_db=self.core_plugin.create_port(ctx, port)
                    data = {'router_id': r1['id'], 'port_id': port_db['id'] }
                    self._create_req('routers', data, r1['id'],
                                     subresource='add_router_interface')

    def test_gw_router_add_interface(self):
        self._test_gw_router_create_add_interface()

    def _test_gw_router_create_remove_interface(self, set_context=False):
        tenant_id = _uuid()
        with self.network(tenant_id=tenant_id) as n_external:
            res = self._create_subnet(self.fmt, n_external['network']['id'],
                                      cidr='10.0.1.0/24', tenant_id=tenant_id)
            s = self.deserialize(self.fmt, res)
            self._set_net_external(s['subnet']['network_id'])
            ext_gw = {'network_id': s['subnet']['network_id']}
            with self.router(tenant_id=tenant_id, external_gateway_info=ext_gw,
                             set_context=set_context) as router1:
                r1 = router1['router']
                self.plugin._process_backlogged_routers()
                r1_after = self._show('routers', r1['id'])['router']
                hd_id = r1_after[HOSTING_DEVICE_ATTR]
                # should have one global router now
                self._verify_created_routers({r1['id']}, hd_id)
                with self.network(tenant_id=tenant_id) as n_internal:
                    res = self._create_subnet(self.fmt, n_internal['network']['id'],
                                              cidr='20.0.1.0/24', tenant_id=tenant_id)
                    s_int = self.deserialize(self.fmt, res)
                    self._set_net_external(s_int['subnet']['network_id'])
                    port = {'port': {'name': 'port',
                                     'network_id': s_int['subnet']['network_id'],
                                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                                     'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                                     'admin_state_up': True,
                                     #'device_id': r1_after['id'],
                                     'device_id': '',
                                     #'device_owner': l3_constants.DEVICE_OWNER_ROUTER_INTF,
                                     'device_owner': '',
                                     'tenant_id': s['subnet']['tenant_id']}}
                    ctx = context.Context('', '', is_admin=True)
                    port_db=self.core_plugin.create_port(ctx, port)
                    data = {'router_id': r1['id'], 'port_id': port_db['id'] }
                    self._create_req('routers', data, r1['id'],
                                     subresource='add_router_interface')
                    self._create_req('routers', data, r1['id'],
                                     subresource='remove_router_interface')

    def test_gw_router_remove_interface(self):
        self._test_gw_router_create_remove_interface()

    def _test_notify_op_agent(self, target_func, *args):
        kargs = [item for item in args]
        kargs.append(self._l3_cfg_agent_mock)
        target_func(*kargs)

    def _validate_ha_fip_ops(self, notifyApi, routers, first_operation):
        # 2 x add gateway (one for user visible router), one for redundancy
        # routers
        # 3 x add interface (one for each router),
        # 1 x update of floatingip (with 3 routers included),
        # 1 x deletion of floatingip (with 3 routers included)
        notify_call_1 = notifyApi.routers_updated.mock_calls[5]
        self.assertEqual(notify_call_1[1][2], first_operation)
        r_ids = {r['id'] for r in notify_call_1[1][1]}
        for r in routers:
            self.assertIn(r['id'], r_ids)
            r_ids.remove(r['id'])
        self.assertEqual(len(r_ids), 0)
        delete_call = notifyApi.routers_updated.mock_calls[6]
        self.assertEqual(delete_call[1][2], 'delete_floatingip')
        r_ids = {r['id'] for r in delete_call[1][1]}
        for r in routers:
            self.assertIn(r['id'], r_ids)
            r_ids.remove(r['id'])
        self.assertEqual(len(r_ids), 0)
        self.assertEqual(7, notifyApi.routers_updated.call_count)

    def _test_ha_floatingip_update_cfg_agent(self, notifyApi):
        with self.subnet() as private_sub:
            with self.port(private_sub) as p_port:
                private_port = p_port['port']
                with self.floatingip_no_assoc(private_sub) as fl_ip:
                    fip = fl_ip['floatingip']
                    routers = self._list('routers')['routers']
                    fip_spec = {'floatingip': {'port_id': private_port['id']}}
                    self._update('floatingips', fip['id'], fip_spec)
        self._validate_ha_fip_ops(notifyApi, routers, 'update_floatingip')

    def test_ha_floatingip_update_cfg_agent(self):
        self._test_notify_op_agent(self._test_ha_floatingip_update_cfg_agent)

class AciAsr1kHARouterTypeDriverTestCase(
        asr1k.Asr1kHARouterTypeDriverTestCase):

    # For the HA tests we need more than one hosting device
    router_type = 'ASR1k_Neutron_router'
    _is_ha_tests = True


class L3CfgAgentAciAsr1kRouterTypeDriverTestCase(
        asr1k.L3CfgAgentAsr1kRouterTypeDriverTestCase):

    _is_ha_tests = True
