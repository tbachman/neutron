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
# @author: Abhishek Raut, Cisco Systems Inc.

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
        pass

    def get_network_profile(self, netp_name):
        """Retrieve a network profile."""
        try:
            return (self.db_session.query(n1kv_models.NetworkProfile).
                    filter_by(name=netp_name).one())
        except sa_exc.NoResultFound:
            return None

    def remove_network_profile(self, netp_name):
        """Delete a network profile."""
        nprofile = self.get_network_profile(netp_name)
        if nprofile:
            self.db_session.delete(nprofile)
            self.db_session.flush()

    def add_policy_profile(self, id, pprofile_name):
        """Create a policy profile."""
        pprofile = n1kv_models.PolicyProfile(id=id, name=pprofile_name)
        self.db_session.add(pprofile)
        self.db_session.flush()
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
            self.db_session.flush()
