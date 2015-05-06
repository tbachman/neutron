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

from neutron.extensions import l3
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.extensions import routerhostingdevice
from neutron.tests.unit.plugins.cisco.l3 import (
    test_l3_routertype_aware_schedulers as cisco_test_case)


_uuid = uuidutils.generate_uuid

AGENT_TYPE_L3_CFG = cisco_constants.AGENT_TYPE_L3_CFG
HOSTING_DEVICE_ATTR = routerhostingdevice.HOSTING_DEVICE_ATTR


class Asr1kRouterTypeDriverTestCase(
        cisco_test_case.L3RoutertypeAwareHostingDeviceSchedulerTestCaseBase):

    # Nexus router type for ASR1k driver tests, why?
    #   - Yes(!), it does not matter and there is only one hosting device for
    #  that router type in the test setup which makes scheduling deterministic
    router_type = 'Nexus_ToR_Neutron_router'

    def _verify_created_routers(self, router_ids, hd_id):
        # tenant routers
        q_p = 'role=None'
        r_ids = {r['id'] for r in self._list(
            'routers', query_params=q_p)['routers']}
        self.assertEqual(len(r_ids), len(router_ids))
        for r_id in r_ids:
            self.assertIn(r_id, router_ids)
        # global routers
        q_p = 'role=%s' % cisco_constants.ROUTER_ROLE_GLOBAL
        g_rtrs = self._list('routers', query_params=q_p)['routers']
        self.assertEqual(len(g_rtrs), 1)
        g_rtr = g_rtrs[0]
        self.assertEqual(g_rtr['name'].endswith(
            hd_id[-cisco_constants.ROLE_ID_LEN:]), True)
        # ensure first routers_updated notification was for global router
        notifier = self.plugin.agent_notifiers[AGENT_TYPE_L3_CFG]
        notify_call = notifier.method_calls[0]
        self.assertEqual(notify_call[0], 'routers_updated')
        updated_routers = notify_call[1][1]
        self.assertEqual(len(updated_routers), 1)
        self.assertEqual(updated_routers[0]['id'], g_rtr['id'])

    def _test_gw_router_create_adds_global_router(self, set_context=False):
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
                hd_id = r1_after[routerhostingdevice.HOSTING_DEVICE_ATTR]
                # should have one global router now
                self._verify_created_routers({r1['id']}, hd_id)
                with self.router(name='router2', tenant_id=tenant_id,
                                 external_gateway_info=ext_gw,
                                 set_context=set_context) as router2:
                    r2 = router2['router']
                    self.plugin._process_backlogged_routers()
                    # should still have only one global router
                    self._verify_created_routers({r1['id'], r2['id']}, hd_id)

    def test_gw_router_create_adds_global_router(self):
        self._test_gw_router_create_adds_global_router()

    def test_gw_router_create_adds_global_router_non_admin(self):
        self._test_gw_router_create_adds_global_router(True)

    def _test_router_create_adds_no_global_router(self, set_context=False):
        with self.router(set_context=set_context) as router:
            r = router['router']
            self.plugin._process_backlogged_routers()
            # tenant routers
            q_p = 'role=None'
            t_rtrs = self._list('routers', query_params=q_p)['routers']
            self.assertEqual(len(t_rtrs), 1)
            t_rtr = t_rtrs[0]
            self.assertEqual(t_rtr['id'], r['id'])
            hd_id = t_rtr[routerhostingdevice.HOSTING_DEVICE_ATTR]
            # global routers
            q_p = 'role=%s' % cisco_constants.ROUTER_ROLE_GLOBAL
            g_rtrs = self._list('routers', query_params=q_p)['routers']
            self.assertEqual(len(g_rtrs), 0)
            #TODO(bobmel): Also check that notification is sent

    def test_router_create_adds_no_global_router(self):
        self._test_router_create_adds_no_global_router()

    def test_router_create_adds_no_global_router_non_admin(self):
        self._test_router_create_adds_no_global_router(False)

    def _verify_updated_routers(self, router_ids, hd_id=None, call_index=1):
        # tenant routers
        q_p = 'role=None'
        r_ids = {r['id'] for r in self._list(
            'routers', query_params=q_p)['routers']}
        self.assertEqual(len(r_ids), len(router_ids))
        for r_id in r_ids:
            self.assertIn(r_id, router_ids)
        # global routers
        q_p = 'role=%s' % cisco_constants.ROUTER_ROLE_GLOBAL
        g_rtrs = self._list('routers', query_params=q_p)['routers']
        if hd_id:
            self.assertEqual(len(g_rtrs), 1)
            g_rtr = g_rtrs[0]
            self.assertEqual(
                g_rtr['name'].endswith(hd_id[-cisco_constants.ROLE_ID_LEN:]),
                True)
            # routers_updated notification call_index is for global router
            notifier = self.plugin.agent_notifiers[AGENT_TYPE_L3_CFG]
            notify_call = notifier.method_calls[call_index]
            self.assertEqual(notify_call[0], 'routers_updated')
            updated_routers = notify_call[1][1]
            self.assertEqual(len(updated_routers), 1)
            self.assertEqual(updated_routers[0]['id'], g_rtr['id'])
        else:
            self.assertEqual(len(g_rtrs), 0)

    def _test_router_update_set_gw_adds_global_router(self, set_context=False):
        tenant_id = _uuid()
        with self.network(tenant_id=tenant_id) as n_external:
            res = self._create_subnet(self.fmt, n_external['network']['id'],
                                      cidr='10.0.1.0/24', tenant_id=tenant_id)
            s = self.deserialize(self.fmt, res)
            self._set_net_external(s['subnet']['network_id'])
            with contextlib.nested(
                self.router(tenant_id=tenant_id, set_context=set_context),
                self.router(name='router2', tenant_id=tenant_id,
                            set_context=set_context)) as (router1, router2):
                r1 = router1['router']
                r2 = router2['router']
                # backlog processing will trigger one routers_updated
                # notification containing r1 and r2
                self.plugin._process_backlogged_routers()
                # should have no global router yet
                r_ids = {r1['id'], r2['id']}
                self._verify_updated_routers(r_ids)
                ext_gw = {'network_id': s['subnet']['network_id']}
                r_spec = {'router': {l3.EXTERNAL_GW_INFO: ext_gw}}
                r1_after = self._update('routers', r1['id'], r_spec)['router']
                hd_id = r1_after[routerhostingdevice.HOSTING_DEVICE_ATTR]
                # should now have one global router
                self._verify_updated_routers(r_ids, hd_id)
                r2_after = self._update('routers', r2['id'], r_spec)['router']
                # should still have only one global router
                self._verify_updated_routers(r_ids, hd_id)

    def test_router_update_set_gw_adds_global_router(self):
        self._test_router_update_set_gw_adds_global_router()

    def test_router_update_set_gw_adds_global_router_non_admin(self):
        self._test_router_update_set_gw_adds_global_router(True)

    def _test_router_update_unset_gw_keeps_global_router(self,
                                                         set_context=False):
        tenant_id = _uuid()
        with self.network(tenant_id=tenant_id) as n_external:
            res = self._create_subnet(self.fmt, n_external['network']['id'],
                                      cidr='10.0.1.0/24', tenant_id=tenant_id)
            s = self.deserialize(self.fmt, res)
            self._set_net_external(s['subnet']['network_id'])
            ext_gw = {'network_id': s['subnet']['network_id']}
            with contextlib.nested(
                self.router(tenant_id=tenant_id, external_gateway_info=ext_gw,
                            set_context=set_context),
                self.router(name='router2', tenant_id=tenant_id,
                            external_gateway_info=ext_gw,
                            set_context=set_context)) as (router1, router2):
                r1 = router1['router']
                r2 = router2['router']
                # backlog processing will trigger one routers_updated
                # notification containing r1 and r2
                self.plugin._process_backlogged_routers()
                r1_after = self._show('routers', r1['id'])['router']
                hd_id = r1_after[routerhostingdevice.HOSTING_DEVICE_ATTR]
                r_ids = {r1['id'], r2['id']}
                # should have one global router now
                self._verify_updated_routers(r_ids, hd_id, 0)
                r_spec = {'router': {l3.EXTERNAL_GW_INFO: None}}
                r1_last = self._update('routers', r1['id'], r_spec)['router']
                # should still have one global router
                self._verify_updated_routers(r_ids, hd_id, 0)
                r2_after = self._update('routers', r2['id'], r_spec)['router']
                # should have no global router now
                self._verify_updated_routers(r_ids)

    def test_router_update_unset_gw_keeps_global_router(self):
        self._test_router_update_unset_gw_keeps_global_router()

    def test_router_update_unset_gw_keeps_global_router_non_admin(self):
        self._test_router_update_unset_gw_keeps_global_router(True)

    def _verify_deleted_routers(self, hd_id=None, id_global_router=None):
        # global routers
        q_p = 'role=%s' % cisco_constants.ROUTER_ROLE_GLOBAL
        g_rtrs = self._list('routers', query_params=q_p)['routers']
        if hd_id:
            self.assertEqual(len(g_rtrs), 1)
            g_rtr = g_rtrs[0]
            self.assertEqual(g_rtr['name'].endswith(
                hd_id[-cisco_constants.ROLE_ID_LEN:]), True)
            return g_rtrs[0]['id']
        else:
            self.assertEqual(len(g_rtrs), 0)
            # ensure last router_deleted notification was for global router
            notifier = self.plugin.agent_notifiers[AGENT_TYPE_L3_CFG]
            notify_call = notifier.method_calls[-1]
            self.assertEqual(notify_call[0], 'router_deleted')
            deleted_router = notify_call[1][1]
            self.assertEqual(deleted_router['id'], id_global_router)

    def _test_gw_router_delete_removes_global_router(self, set_context=False):
        tenant_id = _uuid()
        with self.network(tenant_id=tenant_id) as n_external:
            res = self._create_subnet(self.fmt, n_external['network']['id'],
                                      cidr='10.0.1.0/24', tenant_id=tenant_id)
            s = self.deserialize(self.fmt, res)
            self._set_net_external(s['subnet']['network_id'])
            ext_gw = {'network_id': s['subnet']['network_id']}
            with contextlib.nested(
                self.router(tenant_id=tenant_id, external_gateway_info=ext_gw,
                            set_context=set_context),
                self.router(name='router2', tenant_id=tenant_id,
                            external_gateway_info=ext_gw,
                            set_context=set_context)) as (router1, router2):
                r1 = router1['router']
                r2 = router2['router']
                self.plugin._process_backlogged_routers()
                r1_after = self._show('routers', r1['id'])['router']
                hd_id = r1_after[routerhostingdevice.HOSTING_DEVICE_ATTR]
                self._delete('routers', r1['id'])
                # should still have the global router
                id_global_router = self._verify_deleted_routers(hd_id)
                self._delete('routers', r2['id'])
                # should be no global router now
                self._verify_deleted_routers(id_global_router=id_global_router)

    def test_gw_router_delete_removes_global_router(self):
        self._test_gw_router_delete_removes_global_router()

    def test_gw_router_delete_removes_global_router_non_admin(self):
        self._test_gw_router_delete_removes_global_router(True)

    def _test_router_delete_removes_no_global_router(self, set_context=False):
        tenant_id = _uuid()
        with self.network(tenant_id=tenant_id) as n_external:
            res = self._create_subnet(self.fmt, n_external['network']['id'],
                                      cidr='10.0.1.0/24', tenant_id=tenant_id)
            s = self.deserialize(self.fmt, res)
            self._set_net_external(s['subnet']['network_id'])
            ext_gw = {'network_id': s['subnet']['network_id']}
            with contextlib.nested(
                self.router(tenant_id=tenant_id, set_context=set_context),
                self.router(name='router2', tenant_id=tenant_id,
                            external_gateway_info=ext_gw,
                            set_context=set_context)) as (router1, router2):
                r1 = router1['router']
                r2 = router2['router']
                self.plugin._process_backlogged_routers()
                r1_after = self._show('routers', r1['id'])['router']
                hd_id = r1_after[routerhostingdevice.HOSTING_DEVICE_ATTR]
                self._delete('routers', r1['id'])
                # should still have the global router
                id_global_router = self._verify_deleted_routers(hd_id)
                self._delete('routers', r2['id'])
                # should be no global router now
                self._verify_deleted_routers(id_global_router=id_global_router)

    def test_router_delete_removes_no_global_router(self):
        self._test_router_delete_removes_no_global_router()

    def test_gw_router_delete_removes_no_global_router_non_admin(self):
        self._test_router_delete_removes_no_global_router(True)
