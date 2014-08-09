# Copyright 2014 OpenStack Foundation
# All rights reserved.
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
# @author: Abhishek Raut (abhraut@cisco.com), Cisco Systems Inc.

"""
ML2 Mechanism Driver for Cisco Nexus1000V distributed virtual switches.
"""

import eventlet

from oslo.config import cfg

from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.common import p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.n1kv import constants as n1kv_const
from neutron.plugins.ml2.drivers.cisco.n1kv import exceptions as n1kv_exc
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_client
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_db

LOG = log.getLogger(__name__)


class N1KVMechanismDriver(api.MechanismDriver):

    def initialize(self):
        self.n1kv_db = n1kv_db.N1kvDbModel()
        self.n1kvclient = n1kv_client.Client()

        # Populate policy profiles from the VSM
        eventlet.spawn(self._poll_policy_profiles)
        # Get VLAN/VXLAN network profiles name
        netp_vlan = cfg.CONF.ml2_cisco_n1kv.default_vlan_network_profile
        netp_vxlan = cfg.CONF.ml2_cisco_n1kv.default_vxlan_network_profile
        # Ensure network profiles are created on the VSM
        self._ensure_network_profiles_created_on_vsm(netp_vlan, netp_vxlan)

    def _poll_policy_profiles(self):
        """Start a green thread to pull policy profiles from VSM."""
        while True:
            self._populate_policy_profiles()
            eventlet.sleep(cfg.CONF.ml2_cisco_n1kv.poll_duration)

    def _populate_policy_profiles(self):
        """Populate all the policy profiles from VSM."""
        try:
            policy_profiles = self.n1kvclient.list_port_profiles()
            vsm_profiles = {}
            plugin_profiles_set = set()
            # Fetch policy profiles from VSM
            for profile_name in policy_profiles:
                profile_id = (policy_profiles[profile_name]
                              [n1kv_const.PROPERTIES][n1kv_const.ID])
                vsm_profiles[profile_id] = profile_name
            # Fetch policy profiles previously populated
            for profile in self.n1kv_db.get_policy_profiles():
                plugin_profiles_set.add(profile.id)
            vsm_profiles_set = set(vsm_profiles)
            # Update database if the profile sets differ.
            if vsm_profiles_set ^ plugin_profiles_set:
                # Add profiles in database if new profiles were created in VSM
                for pid in vsm_profiles_set - plugin_profiles_set:
                    self.n1kv_db.add_policy_profile(pid, vsm_profiles[pid])
                # Delete profiles from database if profiles were deleted in VSM
                for pid in plugin_profiles_set - vsm_profiles_set:
                    self.n1kv_db.remove_policy_profile(pid)
        except (n1kv_exc.VSMError,
                n1kv_exc.VSMConnectionFailed):
            LOG.warning(_('No policy profile populated from VSM'))

    def _ensure_network_profiles_created_on_vsm(netp_vlan_name,
                                                netp_vxlan_name):
        # Make sure logical networks and network profiles exist
        # on the VSM
        netp_vlan = self.n1kv_db.get_network_profile(netp_vlan_name)
        netp_vxlan = self.n1kv_db.get_network_profile(netp_vxlan_name)
        if not netp_vlan:
            # Create a network profile of type VLAN on VSM and Neutron
            netp_vlan = self.n1kv_db.add_network_profile(netp_vlan_name,
                                                         p_const.TYPE_VLAN)
        if not netp_vxlan:
            # Create a network profile of type VXLAN on VSM and Neutron
            netp_vxlan = self.n1kv_db.add_network_profile(netp_vxlan_name,
                                                          p_const.TYPE_VXLAN)

    def create_network_precommit(self, context):
        pass

    def create_network_postcommit(self, context):
        pass

    def update_network_precommit(self, context):
        pass

    def update_network_postcommit(self, context):
        pass

    def delete_network_precommit(self, context):
        pass

    def delete_network_postcommit(self, context):
        pass

    def create_subnet_precommit(self, context):
        pass

    def create_subnet_postcommit(self, context):
        pass

    def update_subnet_precommit(self, context):
        pass

    def update_subnet_postcommit(self, context):
        pass

    def delete_subnet_precommit(self, context):
        pass

    def delete_subnet_postcommit(self, context):
        pass

    def create_port_precommit(self, context):
        pass

    def create_port_postcommit(self, context):
        pass

    def update_port_precommit(self, context):
        pass

    def update_port_postcommit(self, context):
        pass

    def delete_port_precommit(self, context):
        pass

    def delete_port_postcommit(self, context):
        pass
