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

from neutron.plugins.cisco.l3 import drivers


class ASR1kL3RouterDriver(drivers.L3RouterBaseDriver):

    def create_router_precommit(self, context, router_context):
        pass

    def create_router_postcommit(self, context, router_context):
        pass

    def update_router_precommit(self, context, router_context):
        pass

    def update_router_postcommit(self, context, router_context):
        b = router_context
        # if router is hosted and router has gateway port:
        #    if global router does not exist for hosting device of router:
        #        create global router on that hosting device
        #    if global router doesn't have port on router's external network:
        #        create port on external network for global router
        pass

    def delete_router_precommit(self, context, router_context):
        pass

    def delete_router_postcommit(self, context, router_context):
        pass

    def schedule_router_precommit(self, context, router_context):
        pass

    def schedule_router_postcommit(self, context, router_context):
        # if router has a gateway port:
        #    if global router does not exist for hosting device of router:
        #        create global router on that hosting device
        #    if global router doesn't have port on router's external network:
        #        create port on external network for global router
        pass

    def unschedule_router_precommit(self, context, router_context):
        pass

    def unschedule_router_postcommit(self, context, router_context):
        # if router is last router on hosting device:
        #    if global router exists for hosting device of router:
        #        delete all ports of that global router
        #        delete that global router
        pass

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