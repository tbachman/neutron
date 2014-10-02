# Copyright (c) 2014 OpenStack Foundation.
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
# @author: Arvind Somya, Cisco Systems, Inc. <asomya@cisco.com>

from oslo.config import cfg

from neutron.common import constants as q_const
from neutron.common import topics
from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_dvrscheduler_db
from neutron.db import l3_gwmode_db
from neutron.openstack.common import importutils
from neutron.plugins.common import constants
from neutron.services.l3_router import l3_router_plugin as router


class NexusL3ServicePlugin(router.L3RouterPlugin,
                           extraroute_db.ExtraRoute_db_mixin,
                           l3_gwmode_db.L3_NAT_db_mixin):
    def __init__(self):
        super(NexusL3ServicePlugin, self).__init__()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    def create_router(self, context, router):
        db_router = super(NexusL3ServicePlugin, self).create_router(
            context, router)

    def update_router(self, context, id, router):
        return super(NexusL3ServicePlugin, self).update_router(context,
                                                               id, router)

    def delete_router(self, context, id):
        return super(NexusL3ServicePlugin, self).delete_router(context, id)

    def add_router_interface(self, context, router_id, interface_info):
        return super(NexusL3ServicePlugin, self).add_router_interface(context,
            router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        return super(NexusL3ServicePlugin, self).remove_router_interface(
            context, router_id, interface_info)

    def create_floatingip(self, context, floating_ip):
        return super(NexusL3ServicePlugin, self).create_floatingip(
            context, floatingip)

    def update_floatingip(self, context, id, floatingip):
        return super(NexusL3ServicePlugin, self).update_floatingip(
            context, id, floatingip)

    def update_floatingip_status(self, context, floatingip_id, status):
        return super(NexusL3ServicePlugin, self).update_floatingip_status(
            context, id, floatingip, status)

    def delete_floatingip(self, context, id):
        return super(NexusL3ServicePlugin, self).delete_floatingip(
            context, id)

    def dissassociate_floatingips(self, context, port_id):
        return super(NexusL3ServicePlugin, self).disassociate_floatingips(
            context, port_id)
