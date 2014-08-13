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

"""
ML2 Mechanism Driver for Cisco Nexus1000V distributed virtual switches.
"""

import eventlet

from oslo.config import cfg

from neutron.common import exceptions as n_exc
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.n1kv import config # noqa
from neutron.plugins.ml2.drivers.cisco.n1kv import constants as n1kv_const
from neutron.plugins.ml2.drivers.cisco.n1kv import exceptions as n1kv_exc
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_client
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_db

LOG = log.getLogger(__name__)


class N1KVMechanismDriver(api.MechanismDriver):

    def initialize(self):
        n1kv_conf = cfg.CONF.ml2_cisco_n1kv
        self.n1kv_db = n1kv_db.N1kvDbModel()
        self.n1kvclient = n1kv_client.Client()

        # Populate policy profiles from the VSM
        eventlet.spawn(self._poll_policy_profiles)
        # Get VLAN/VXLAN network profiles name
        self.netp_vlan_name = (cfg.CONF.ml2_cisco_n1kv.
                               default_vlan_network_profile)
        self.netp_vxlan_name = (cfg.CONF.ml2_cisco_n1kv.
                                default_vxlan_network_profile)
        # Ensure network profiles are created on the VSM
        self._ensure_network_profiles_created_on_vsm()

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

    def _ensure_network_profiles_created_on_vsm(self):
        # Make sure logical networks and network profiles exist
        # on the VSM
        try:
            netp_vlan = self.n1kv_db.get_network_profile_by_type(p_const.TYPE_VLAN)
        except n1kv_exc.NetworkProfileNotFound:
            # Create a network profile of type VLAN in Neutron DB
            netp_vlan = self.n1kv_db.add_network_profile(self.netp_vlan_name,
                                                         p_const.TYPE_VLAN)
            # Create a network profile of type VLAN on the VSM
            self.n1kvclient.create_network_segment_pool(netp_vlan)
        try:
            netp_vxlan = self.n1kv_db.get_network_profile_by_type(p_const.TYPE_VXLAN)
        except n1kv_exc.NetworkProfileNotFound:
            # Create a network profile of type VXLAN in Neutron DB
            netp_vxlan = self.n1kv_db.add_network_profile(self.netp_vxlan_name,
                                                          p_const.TYPE_VXLAN)
            # Create a network profile of type VXLAN on the VSM
            self.n1kvclient.create_network_segment_pool(netp_vxlan)

    def create_network_precommit(self, context):
        """Update network binding information."""
        network = context.current
        segment = context.network_segments[0]
        network_type = segment['network_type']
        if network_type not in [p_const.TYPE_VLAN, p_const.TYPE_VXLAN]:
            msg = _("Cisco Nexus1000V: Failed to create unsupported type of "
                    "network. Network type VLAN and VXLAN supported.")
            raise n_exc.InvalidInput(error_message=msg) 
        netp = self.n1kv_db.get_network_profile_by_type(network_type)
        kwargs = {"network_id": network['id'],
                  "network_type": network_type,
                  "segmentation_id": segment['segmentation_id'],
                  "netp_id": netp['id']}
        self.n1kv_db.add_network_binding(**kwargs)

    def create_network_postcommit(self, context):
        """Send network parameters to the VSM."""
        network = context.current
        segment = context.network_segments[0]
        network_type = segment['network_type']
        netp = self.n1kv_db.get_network_profile_by_type(network_type)
        try:
            self.n1kvclient.create_network_segment(network, netp)
        except(n1kv_exc.VSMError, n1kv_exc.VSMConnectionFailed) as e:
            LOG.info(e.message)
            raise ml2_exc.MechanismDriverError()
        LOG.info(_("Create network(postcommit) succeeded for network: "
                   "%(network_id)s of type: %(network_type)s with segment "
                   "id: %(segment_id)s"),
                 {"network_id": network['id'],
                  "network_type": network_type,
                  "segment_id": segment['segmentation_id']})

    def update_network_postcommit(self, context):
        """Send updated network parameters to the VSM."""
        updated_network = context.current
        old_network = context.original
        # Perform network update on VSM in case of network name change only.
        if updated_network['name'] != old_network['name']:
            try:
                self.n1kvclient.update_network_segment(updated_network)
            except(n1kv_exc.VSMError, n1kv_exc.VSMConnectionFailed) as e:
                LOG.info(e.message)
                raise ml2_exc.MechanismDriverError()
        LOG.info(_("Update network(postcommit) succeeded for network: %s",
                   old_network['id']))

    def delete_network_postcommit(self, context):
        """Send network delete request to the VSM."""
        network = context.current
        segment = context.network_segments[0]
        network_type = segment['network_type']
        try:
            self.n1kvclient.delete_network_segment(network['id'])
        except(n1kv_exc.VSMError, n1kv_exc.VSMConnectionFailed) as e:
            LOG.info(e.message)
            raise ml2_exc.MechanismDriverError()
        LOG.info(_("Delete network(postcommit) succeeded for network: "
                   "%(network_id)s of type: %(network_type)s with segment "
                   "id: %(segment_id)s"),
                 {"network_id": network['id'],
                  "network_type": network_type,
                  "segment_id": segment['segmentation_id']})

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
