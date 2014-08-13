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

import sqlalchemy.orm.exc as sa_exc

import neutron.db.api as db
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.cisco.n1kv import exceptions as n1kv_exc
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_models


LOG = logging.getLogger(__name__)


class N1kvDbModel(object):

    """DB Model to manage all Nexus1000V DB interactions."""

    def __init__(self):
        self.db_session = db.get_session()

    def add_network_profile(self, netp_name, netp_type):
        """Create a network profile."""
        netp = n1kv_models.NetworkProfile(name=netp_name,
                                          segment_type=netp_type)
        self.db_session.add(netp)
        return netp

    def get_network_profile_by_type(self, segment_type):
        """Retrieve a network profile using its type."""
        try:
            return (self.db_session.query(n1kv_models.NetworkProfile).
                    filter_by(segment_type=segment_type).one())
        except sa_exc.NoResultFound:
            raise n1kv_exc.NetworkProfileNotFound(profile=segment_type)

    def add_policy_profile(self, id, pprofile_name):
        """Create a policy profile."""
        pprofile = n1kv_models.PolicyProfile(id=id, name=pprofile_name)
        self.db_session.add(pprofile)
        return pprofile

    def get_policy_profiles(self):
        """Retrieve all policy profiles."""
        return self.db_session.query(n1kv_models.PolicyProfile)

    def remove_policy_profile(self, pprofile_id):
        """Delete a policy profile."""
        pprofile = (self.db_session.query(n1kv_models.PolicyProfile).
                    filter_by(id=pprofile_id).first())
        if pprofile:
            self.db_session.delete(pprofile)

    def add_network_binding(self,
                            network_id,
                            network_type,
                            segmentation_id,
                            netp_id):
        """
        Create the network to network profile binding.

        :param network_id: UUID representing the network
        :param network_type: string representing type of network (VLAN, VXLAN)
        :param segmentation_id: integer representing VLAN or VXLAN ID
        :param netp_id: network profile ID based on which this network
                        is created
        """
        binding = n1kv_models.N1kvNetworkBinding(network_id=network_id,
                                                 network_type=network_type,
                                                 segmentation_id=segmentation_id,
                                                 profile_id=netp_id)
        self.db_session.add(binding)
        return binding

    def get_network_binding(self, network_id):
        """Retrieve network binding."""
        try:
            return (self.db_session.query(n1kv_models.N1kvNetworkBinding).
                    filter_by(network_id=network_id).one())
        except sa_exc.NoResultFound:
            raise n1kv_exc.NetworkBindingNotFound(network_id=network_id)

    def remove_network_binding(self, network_id):
        """Delete the network to network profile binding."""
        binding = self.get_network_binding(network_id)
        if binding:
            self.db_sesion.delete(binding)
