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

from oslo.config import cfg

from neutron.common import constants as n_const
from neutron.common import exceptions as n_exc
from neutron.extensions import portbindings
from neutron.openstack.common import excutils
from neutron.openstack.common.gettextutils import _LI, _LW
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.n1kv import config  # noqa
from neutron.plugins.ml2.drivers.cisco.n1kv import constants as n1kv_const
from neutron.plugins.ml2.drivers.cisco.n1kv import exceptions as n1kv_exc
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_client
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_db

LOG = log.getLogger(__name__)


class N1KVMechanismDriver(api.MechanismDriver):

    def initialize(self):
        self.n1kvclient = n1kv_client.Client()

        # Populate policy profiles from the VSM
        self._populate_policy_profiles()
        # Get VLAN/VXLAN network profiles name
        self.netp_vlan_name = (cfg.CONF.ml2_cisco_n1kv.
                               default_vlan_network_profile)
        self.netp_vxlan_name = (cfg.CONF.ml2_cisco_n1kv.
                                default_vxlan_network_profile)
        # Ensure network profiles are created on the VSM
        self._ensure_network_profiles_created_on_vsm()
        self.vif_type = portbindings.VIF_TYPE_OVS
        self.vif_details = {portbindings.CAP_PORT_FILTER: True,
                            portbindings.OVS_HYBRID_PLUG: True}
        self.supported_network_types = [p_const.TYPE_VLAN, p_const.TYPE_VXLAN]

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
            for profile in n1kv_db.get_policy_profiles():
                plugin_profiles_set.add(profile.id)
            vsm_profiles_set = set(vsm_profiles)
            # Update database if the profile sets differ.
            if vsm_profiles_set.symmetric_difference(plugin_profiles_set):
                # Add profiles in database if new profiles were created in VSM
                for pid in vsm_profiles_set.difference(plugin_profiles_set):
                    n1kv_db.add_policy_profile(pid, vsm_profiles[pid])
                # Delete profiles from database if profiles were deleted in VSM
                for pid in plugin_profiles_set.difference(vsm_profiles_set):
                    n1kv_db.remove_policy_profile(pid)
        except (n1kv_exc.VSMError, n1kv_exc.VSMConnectionFailed):
            with excutils.save_and_reraise_exception(reraise=False):
                LOG.warning(_LW('No policy profile populated from VSM'))

    def _ensure_network_profiles_created_on_vsm(self, db_session=None):
        # Make sure logical networks and network profiles exist
        # on the VSM
        try:
            netp_vlan = n1kv_db.get_network_profile_by_type(p_const.TYPE_VLAN)
        except n1kv_exc.NetworkProfileNotFound:
            # Create a network profile of type VLAN in Neutron DB
            netp_vlan = n1kv_db.add_network_profile(self.netp_vlan_name,
                                                    p_const.TYPE_VLAN,
                                                    db_session)
            try:
                # Create a network profile of type VLAN on the VSM
                self.n1kvclient.create_network_segment_pool(netp_vlan)
            # Catch any exception here and cleanup if so
            except (n1kv_exc.VSMConnectionFailed, n1kv_exc.VSMError):
                with excutils.save_and_reraise_exception():
                    n1kv_db.remove_network_profile(netp_vlan.id, db_session)
        try:
            netp_vxlan = n1kv_db.get_network_profile_by_type(
                p_const.TYPE_VXLAN)
        except n1kv_exc.NetworkProfileNotFound:
            # Create a network profile of type VXLAN in Neutron DB
            netp_vxlan = n1kv_db.add_network_profile(self.netp_vxlan_name,
                                                     p_const.TYPE_VXLAN,
                                                     db_session)
            try:
                # Create a network profile of type VXLAN on the VSM
                self.n1kvclient.create_network_segment_pool(netp_vxlan)
            # Catch any exception here and cleanup if so
            except (n1kv_exc.VSMConnectionFailed, n1kv_exc.VSMError):
                with excutils.save_and_reraise_exception():
                    n1kv_db.remove_network_profile(netp_vxlan.id, db_session)

    def _validate_segment_id_for_nexus(self, segment_id, network_type):
        """Validate the segment id for a given network type."""
        is_segment_valid = True
        if (network_type == p_const.TYPE_VLAN and
            (segment_id in range(n1kv_const.NEXUS_VLAN_RESERVED_MIN,
                                 n1kv_const.NEXUS_VLAN_RESERVED_MAX + 1))):
            is_segment_valid = False
        elif (network_type == p_const.TYPE_VXLAN and
              segment_id < n1kv_const.NEXUS_VXLAN_MIN):
            is_segment_valid = False
        if not is_segment_valid:
            msg = (_("Segment ID: %(seg_id)s for network type: %(net_type)s "
                     "is unsupported on Cisco Nexus devices.") %
                   {"seg_id": segment_id,
                    "net_type": network_type})
            raise n_exc.InvalidInput(error_message=msg)

    def create_network_precommit(self, context):
        """Update network binding information."""
        network = context.current
        segment = context.network_segments[0]
        network_type = segment['network_type']
        session = context._plugin_context.session
        self._validate_segment_id_for_nexus(segment['segmentation_id'],
                                            network_type)
        if network_type not in self.supported_network_types:
            msg = (_("Cisco Nexus1000V: Failed to create unsupported network "
                     "type: %s. Network type VLAN and VXLAN "
                     "supported.") % network_type)
            raise n_exc.InvalidInput(error_message=msg)
        # Try to find the network profile
        try:
            netp = n1kv_db.get_network_profile_by_type(network_type, session)
        # If not found, try creating profiles before failing
        except n1kv_exc.NetworkProfileNotFound:
            self._ensure_network_profiles_created_on_vsm()
            try:
                netp = n1kv_db.get_network_profile_by_type(network_type,
                                                           session)
            # If not found again, raise driver error
            except n1kv_exc.NetworkProfileNotFound:
                with excutils.save_and_reraise_exception(reraise=False):
                    raise ml2_exc.MechanismDriverError()

        kwargs = {"network_id": network['id'],
                  "network_type": network_type,
                  "db_session": session,
                  "segment_id": segment['segmentation_id'],
                  "netp_id": netp['id']}
        n1kv_db.add_network_binding(**kwargs)

    def create_network_postcommit(self, context):
        """Send network parameters to the VSM."""
        network = context.current
        segment = context.network_segments[0]
        network_type = segment['network_type']
        session = context._plugin_context.session
        netp = n1kv_db.get_network_profile_by_type(network_type, session)
        try:
            self.n1kvclient.create_network_segment(network, netp)
        except(n1kv_exc.VSMError, n1kv_exc.VSMConnectionFailed) as e:
            with excutils.save_and_reraise_exception(reraise=False):
                LOG.info(e.message)
                raise ml2_exc.MechanismDriverError()
        LOG.info(_LI("Create network(postcommit) succeeded for network: "
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
                with excutils.save_and_reraise_exception(reraise=False):
                    LOG.info(e.message)
                    raise ml2_exc.MechanismDriverError()
        LOG.info(_LI("Update network(postcommit) succeeded for network: %s") %
                 old_network['id'])

    def delete_network_postcommit(self, context):
        """Send network delete request to the VSM."""
        network = context.current
        segment = context.network_segments[0]
        network_type = segment['network_type']
        try:
            self.n1kvclient.delete_network_segment(network['id'], network_type)
        except(n1kv_exc.VSMError, n1kv_exc.VSMConnectionFailed) as e:
            with excutils.save_and_reraise_exception(reraise=False):
                LOG.info(e.message)
                raise ml2_exc.MechanismDriverError()
        LOG.info(_LI("Delete network(postcommit) succeeded for network: "
                     "%(network_id)s of type: %(network_type)s with segment "
                     "ID: %(segment_id)s"),
                 {"network_id": network['id'],
                  "network_type": network_type,
                  "segment_id": segment['segmentation_id']})

    def create_port_precommit(self, context):
        """Create port to policy profile bindings."""
        port = context.current
        session = context._plugin_context.session
        try:
            policy_profile = n1kv_db.get_policy_profile_by_name(
                cfg.CONF.ml2_cisco_n1kv.default_policy_profile, session)
        except n1kv_exc.PolicyProfileNotFound as e:
            with excutils.save_and_reraise_exception(reraise=False):
                LOG.info(e.message)
                raise ml2_exc.MechanismDriverError()
        n1kv_db.add_policy_binding(port['id'], policy_profile.id, session)

    def create_port_postcommit(self, context):
        """Send port parameters to the VSM."""
        port = context.current
        session = context._plugin_context.session
        policy_profile = n1kv_db.get_policy_profile_by_name(
            cfg.CONF.ml2_cisco_n1kv.default_policy_profile, session)
        vmnetwork_name = "%s%s_%s" % (n1kv_const.VM_NETWORK_PREFIX,
                                      policy_profile.id,
                                      port['network_id'])
        try:
            self.n1kvclient.create_n1kv_port(port,
                                             vmnetwork_name,
                                             policy_profile)
        except(n1kv_exc.VSMError, n1kv_exc.VSMConnectionFailed) as e:
            with excutils.save_and_reraise_exception(reraise=False):
                LOG.info(e.message)
                raise ml2_exc.MechanismDriverError()
        LOG.info(_LI("Create port(postcommit) succeeded for port: "
                     "%(id)s on network: %(network_id)s with policy "
                     "profile ID: %(profile_id)s"),
                 {"network_id": port['network_id'],
                  "id": port['id'],
                  "profile_id": policy_profile.id})

    def delete_port_postcommit(self, context):
        """Send delete port notification to the VSM."""
        port = context.current
        session = context._plugin_context.session
        policy_profile = n1kv_db.get_policy_profile_by_name(
            cfg.CONF.ml2_cisco_n1kv.default_policy_profile, session)
        vmnetwork_name = "%s%s_%s" % (n1kv_const.VM_NETWORK_PREFIX,
                                      policy_profile.id,
                                      port['network_id'])
        try:
            self.n1kvclient.delete_n1kv_port(vmnetwork_name, port['id'])
        except(n1kv_exc.VSMError, n1kv_exc.VSMConnectionFailed) as e:
            with excutils.save_and_reraise_exception(reraise=False):
                LOG.info(e.message)
                raise ml2_exc.MechanismDriverError()
        LOG.info(_LI("Delete port(postcommit) succeeded for port: "
                     "%(id)s on network: %(network_id)s with policy "
                     "profile ID: %(profile_id)s"),
                 {"network_id": port['network_id'],
                  "id": port['id'],
                  "profile_id": policy_profile.id})

    def bind_port(self, context):
        segments = context.network.network_segments
        for segment in segments:
            if segment[api.NETWORK_TYPE] in self.supported_network_types:
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.vif_details,
                                    status=n_const.PORT_STATUS_ACTIVE)
                return
            else:
                LOG.info(_LI("Port binding rejected for segment ID %(id)s, "
                             "segment %(segment)s and network type "
                             "%(nettype)s"),
                         {'id': segment[api.ID],
                          'segment': segment[api.SEGMENTATION_ID],
                          'nettype': segment[api.NETWORK_TYPE]})
