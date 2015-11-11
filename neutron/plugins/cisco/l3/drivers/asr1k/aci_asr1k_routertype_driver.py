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

from oslo_config import cfg

from neutron.common import constants as l3_constants
from neutron.db import l3_db
from neutron.extensions import l3
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.db.l3 import ha_db
from neutron.plugins.cisco.db.l3.l3_router_appliance_db import (
    L3RouterApplianceDBMixin)
from neutron.plugins.cisco.extensions import routerhostingdevice
from neutron.plugins.cisco.extensions import routerrole
from neutron.plugins.cisco.extensions import routertype
from neutron.plugins.cisco.extensions import routertypeawarescheduler
#from neutron.plugins.cisco.l3 import drivers
from neutron.plugins.cisco.l3.drivers import driver_context
from neutron.plugins.cisco.l3.drivers.asr1k import (
    asr1k_routertype_driver as asr1k)
from neutron.plugins.common import constants

from apicapi import apic_mapper
from apic_ml2.neutron.plugins.ml2.drivers.cisco.apic import mechanism_apic
from neutron.common import exceptions as n_exc


HOSTING_DEVICE_ATTR = routerhostingdevice.HOSTING_DEVICE_ATTR
ROUTER_ROLE_GLOBAL = cisco_constants.ROUTER_ROLE_GLOBAL
ROUTER_ROLE_LOGICAL_GLOBAL = cisco_constants.ROUTER_ROLE_LOGICAL_GLOBAL

TENANT_HSRP_GRP_RANGE = 1
TENANT_HSRP_GRP_OFFSET = 1064
EXT_HSRP_GRP_RANGE = 1
EXT_HSRP_GRP_OFFSET = 1064

N_ROUTER_PREFIX = 'nrouter-'
DEV_NAME_LEN = 14

class InterTenantRouterInterfaceNotAllowedOnPerTenantContext(n_exc.BadRequest):
    message = _("Cannot attach s router interface to a network owned by "
                "another tenant when per_tenant_context is enabled.")

class AciASR1kL3RouterDriver(asr1k.ASR1kL3RouterDriver):

    def __init__(self):
        super(AciASR1kL3RouterDriver, self).__init__()
        self.manager = mechanism_apic.APICMechanismDriver.get_apic_manager()
        self.name_mapper = mechanism_apic.NameMapper(self.manager.apic_mapper)
        self._aci_mech_driver = None
        self._ml2_plugin = None
        self.synchronizer = None

    def sync_init(f):
        def inner(inst, *args, **kwargs):
            if not inst.synchronizer:
                inst.synchronizer = (
                    mechanism_apic.APICMechanismDriver.
                    get_router_synchronizer(inst))
                inst.synchronizer.sync_router()
            return f(inst, *args, **kwargs)
        return inner

    @property
    def ml2_plugin(self):
        if not self._ml2_plugin:
            self._ml2_plugin = manager.NeutronManager.get_plugin()
        return self._ml2_plugin

    @property
    def aci_mech_driver(self):
        if not self._aci_mech_driver:
            self._aci_mech_driver = (
                self.ml2_plugin.mechanism_manager.mech_drivers[
                    'cisco_apic_ml2'].obj)
        return self._aci_mech_driver

    def _map_names(self, context, tenant_id, router, network, subnet):
        context._plugin = self
        with apic_mapper.mapper_context(context) as ctx:
            atenant_id = tenant_id and self.name_mapper.tenant(ctx, tenant_id)
            arouter_id = router and router['id'] and self.name_mapper.router(
                ctx, router['id'], openstack_owner=router['tenant_id'])
            anet_id = (network and network['id'] and
                       self.name_mapper.endpoint_group(ctx, network['id']))
            asubnet_id = subnet and subnet['id'] and self.name_mapper.subnet(
                ctx, subnet['id'])
        return atenant_id, arouter_id, anet_id, asubnet_id

    def _get_router_id_from_port(self, r_port_context):
        current = r_port_context.current
        if (current['device_owner'] != l3_constants.DEVICE_OWNER_ROUTER_GW and
                current['device_owner'] != l3_constants.DEVICE_OWNER_ROUTER_INTF):
            # TODO: raise exception?
            pass

        # Do we guard against key errors?
        router_id = current['device_id']
        return router_id

    def add_router_interface_precommit(self, context, r_port_context):
        pass

    def remove_router_interface_precommit(self, context, r_port_context):
        router_id = self._get_router_id_from_port(r_port_context)
        port = r_port_context.current
        network_id = port['network_id']
        port_id = port['id']

        network = self.ml2_plugin.get_network(context, port['network_id'])
        tenant_id = network['tenant_id']

        with context.session.begin(subtransactions=True):
            router_db = self._l3_plugin._get_router( context, router_id)
        # Map openstack IDs to APIC IDs
        atenant_id, arouter_id, anetwork_id, _ = self._map_names(
            context, tenant_id, router_db, network, None)

        # Program APIC
        self.manager.remove_router_interface(
            self.aci_mech_driver._get_network_aci_tenant(network),
            arouter_id, anetwork_id,
            app_profile_name=self.aci_mech_driver._get_network_app_profile(
                network))
        self.ml2_plugin.update_port_status(context, port_id,
                                           l3_constants.PORT_STATUS_DOWN)

    def add_router_interface_postcommit(self, context, r_port_context):
        super(AciASR1kL3RouterDriver, self).add_router_interface_postcommit(
            context, r_port_context)
        port = r_port_context.current
        router_id = r_port_context.current_router

        # Update router's state first
        with context.session.begin(subtransactions=True):
            router_db = self._l3_plugin._get_router(context, router_id)
        router = driver_context.RouterContext(router_db)
        self.update_router_postcommit(context, router)

        network = self.ml2_plugin.get_network(context, port['network_id'])
        tenant_id = network['tenant_id']
        if (tenant_id != router_db['tenant_id'] and
                self.aci_mech_driver.per_tenant_context and
                not self.aci_mech_driver._is_nat_enabled_on_ext_net(network)):
            # This operation is disallowed. Can't trespass VRFs without NAT.
            raise InterTenantRouterInterfaceNotAllowedOnPerTenantContext()

        # Map openstack IDs to APIC IDs
        atenant_id, arouter_id, anetwork_id, _ = self._map_names(
            context, tenant_id, router_db, network, None)

        # Program APIC
        self.manager.add_router_interface(
            self.aci_mech_driver._get_network_aci_tenant(network),
            arouter_id, anetwork_id,
            app_profile_name=self.aci_mech_driver._get_network_app_profile(
                network))
        self.ml2_plugin.update_port_status(context, port['id'],
                                           l3_constants.PORT_STATUS_ACTIVE)

    def create_router_postcommit(self, context, router_context):
        pass

    def delete_floatingip_precommit(self, context, fip_context):
        pass

    def delete_router_postcommit(self, context, router_context):
        pass

    def remove_router_interface_postcommit(self, context, r_port_context):
        pass

    def schedule_router_postcommit(self, context, router_context):
        super(AciASR1kL3RouterDriver, self).schedule_router_postcommit(
            context, router_context)
        pass

    def schedule_router_precommit(self, context, router_context):
        pass

    def unschedule_router_postcommit(self, context, router_context):
        super(AciASR1kL3RouterDriver, self).unschedule_router_postcommit(
            context, router_context)
        pass

    def unschedule_router_precommit(self, context, router_context):
        pass

    def update_floatingip_precommit(self, context, fip_context):
        pass

    def update_router_precommit(self, context, router_context):
        pass

    def delete_router_precommit(self, context, router_context):
        context._plugin = self
        router = router_context.current
        router_id = router['id']
        with apic_mapper.mapper_context(context) as ctx:
            arouter_id = router_id and self.name_mapper.router(
                ctx, router['id'], openstack_owner=router['id'])
        self.manager.delete_router(arouter_id)

    @sync_init
    def update_router_postcommit(self, context, router_context):
        super(AciASR1kL3RouterDriver, self).update_router_postcommit(
            context, router_context)
        context._plugin = self
        router = router_context.current
        router_id = router['id']
        with apic_mapper.mapper_context(context) as ctx:
            arouter_id = router['id'] and self.name_mapper.router(
                ctx, router['id'], openstack_owner=router['tenant_id'])
            tenant_id = self.aci_mech_driver._get_router_aci_tenant(router)

        with self.manager.apic.transaction() as trs:
            vrf = self.aci_mech_driver._get_tenant_vrf(router['tenant_id'])
            self.manager.create_router(arouter_id, owner=vrf['aci_tenant'],
                                       transaction=trs,
                                       context=vrf['aci_name'])
            if router['admin_state_up']:
                self.manager.enable_router(arouter_id, owner=tenant_id,
                                           transaction=trs)
            else:
                self.manager.disable_router(arouter_id, owner=tenant_id,
                                            transaction=trs)


    # Router API

    @sync_init
    def create_router_precommit(self, context, router_context):
        pass

    def _notify_port_update(self, port_id):
        l2 = mechanism_apic.APICMechanismDriver.get_driver_instance()
        if l2 and port_id:
            l2.notify_port_update(port_id)

    def _create_floatingip(self, context, floatingip):
        port_id = floatingip.get('floatingip', {}).get('port_id')
        self._notify_port_update(port_id)

    def _update_floatingip(self, context, id, floatingip):
        port_id = [floatingip.get('port_id')]
        port_id.append(floatingip.get('floatingip', {}).get('port_id'))
        for p in port_id:
            self._notify_port_update(p)

    def update_floatingip_postcommit(self, context, fip_context):
        floatingip = fip_context.current
        if fip_context._original_fip:
            self._update_floatingip(context, floatingip['id'], floatingip)
        else:
            self._create_floatingip(context, floatingip)

    def delete_floatingip_postcommit(self, context, fip_context):
        floatingip = fip_context.current
        port_id = floatingip.get('port_id')
        self._notify_port_update(port_id)
