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

from neutron.extensions import l3
from neutron import manager
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.extensions import routerhostingdevice
from neutron.plugins.cisco.extensions import routertype
from neutron.plugins.cisco.l3 import drivers
from neutron.plugins.common import constants


class ASR1kL3RouterDriver(drivers.L3RouterBaseDriver):

    def create_router_precommit(self, context, router_context):
        pass

    def create_router_postcommit(self, context, router_context):
        pass

    def update_router_precommit(self, context, router_context):
        pass

    def update_router_postcommit(self, context, router_context):
        # Whenever a gateway is added to, or removed from, a router hosted on
        # a hosting device, we must ensure that a global router is running
        # (for add operation) or not running (for remove operation) on that
        # hosting device.
        current = router_context.current
        hd_id = current[routerhostingdevice.HOSTING_DEVICE_ATTR]
        if hd_id is None:
            return
        if current['gw_port_id']:
            self._conditionally_add_global_router(context, hd_id, current)
        else:
            self._conditionally_remove_global_router(context, hd_id, True)
            # if router is hosted and router has gateway port:
            #    if global router does not exist for hosting device of router:
            #        create global router on that hosting device
            #    if global router doesn't have port on router's external
            #    network:
            #        create port on external network for global router

    def delete_router_precommit(self, context, router_context):
        pass

    def delete_router_postcommit(self, context, router_context):
        pass

    def schedule_router_precommit(self, context, router_context):
        pass

    def _global_router_name(self, hosting_device_id):
        return '%s-%s' % (
            cisco_constants.ROLE_PREFIX,
            hosting_device_id[-cisco_constants.ROLE_ID_LEN:])

    def _conditionally_add_global_router(self, context, hosting_device_id,
                                         router):
        filters = {
            routerhostingdevice.HOSTING_DEVICE_ATTR: [hosting_device_id],
            'role': [cisco_constants.ROUTER_ROLE_GLOBAL]}
        global_routers = self._l3_plugin.get_routers(context,
                                                     filters=filters)
        if not global_routers:
            # must create global router on hosting device
            ext_nw = router[l3.EXTERNAL_GW_INFO]['network_id']
            r_spec = {'router': {
                # global routers are not tied to any tenant
                'tenant_id': '',
                'name': self._global_router_name(hosting_device_id),
                'admin_state_up': True,
                l3.EXTERNAL_GW_INFO: {'network_id': ext_nw}}}
            r = self._l3_plugin.do_create_router(
                context, r_spec, router[routertype.TYPE_ATTR], False, True,
                hosting_device_id, cisco_constants.ROUTER_ROLE_GLOBAL)
            self._l3_plugin.add_type_and_hosting_device_info(
                context.elevated(), r)
            for ni in self._l3_plugin.get_notifiers(context, [r]):
                if ni['notifier']:
                    ni['notifier'].routers_updated(context, ni['routers'])

    def schedule_router_postcommit(self, context, router_context):
        # When the hosting device hosts a Neutron router with external
        # connectivity, a "global" router (modeled as a Neutron router) must
        # also run on the hosting device (outside of any VRF) to enable the
        # connectivity.
        current = router_context.current
        hd_id = current[routerhostingdevice.HOSTING_DEVICE_ATTR]
        if current['gw_port_id'] and hd_id is not None:
            self._conditionally_add_global_router(context, hd_id, current)

    def unschedule_router_precommit(self, context, router_context):
        pass

    def _conditionally_remove_global_router(self, context, hosting_device_id,
                                            update_operation=False):
        filters = {
            routerhostingdevice.HOSTING_DEVICE_ATTR: [hosting_device_id]}
        invert_filters = {'gw_port_id': [None]}
        num_rtrs = self._l3_plugin.get_routers_count_extended(
            context, filters=filters, invert_filters=invert_filters)
        if ((num_rtrs <= 2 and update_operation is False) or
                (num_rtrs <= 1 and update_operation is True)):
            # there are one or two routers left and one of them may be a
            # global router, which can then be deleted
            filters['role'] = [cisco_constants.ROUTER_ROLE_GLOBAL]
            global_routers = self._l3_plugin.get_routers(
                context, filters=filters)
            if global_routers:
                # can remove the global router as it will no longer be used
                self._l3_plugin.delete_router(
                    context, global_routers[0]['id'], unschedule=False)

    def unschedule_router_postcommit(self, context, router_context):
        # When there is no longer any router with external gateway hosted on
        # a hosting device, the global router on that hosting device can also
        # be removed.
        current = router_context.current
        hd_id = current[routerhostingdevice.HOSTING_DEVICE_ATTR]
        if current['gw_port_id'] and hd_id is not None:
            self._conditionally_remove_global_router(context, hd_id)

    def add_router_interface_precommit(self, context, r_port_context):
        pass

    def add_router_interface_postcommit(self, context, r_port_context):
        pass

    def remove_router_interface_precommit(self, context, r_port_context):
        pass

    def remove_router_interface_postcommit(self, context, r_port_context):
        pass

    def update_floatingip_precommit(self, context, fip_context):
        pass

    def update_floatingip_postcommit(self, context, fip_context):
        pass

    def delete_floatingip_precommit(self, context, fip_context):
        pass

    def delete_floatingip_postcommit(self, context, fip_context):
        pass

    @property
    def _l3_plugin(self):
        return manager.NeutronManager.get_service_plugins().get(
            constants.L3_ROUTER_NAT)
