# Copyright 2014 Cisco Systems, Inc.
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

import eventlet
from oslo.config import cfg
from sqlalchemy.orm import exc

from neutron.api import extensions
import neutron.db.api as db
from neutron.db import common_db_mixin as base_db
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.cisco import n1kv
from neutron.plugins.ml2.drivers.cisco.n1kv import config # noqa
from neutron.plugins.ml2.drivers.cisco.n1kv import constants as n1kv_const
from neutron.plugins.ml2.drivers.cisco.n1kv import exceptions as n1kv_exc
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_client
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_db
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_models
from neutron.plugins.ml2.drivers.cisco.n1kv import policy_profile

class PolicyProfile_db_mixin(policy_profile.PolicyProfilePluginBase,
                             base_db.CommonDbMixin):
    """Policy Profile Mixin class."""

    def _make_policy_profile_dict(self, policy_profile, fields=None):
        res = {"id": policy_profile["id"], "name": policy_profile["name"]}
        return self._fields(res, fields)

    def _add_policy_profile(self, id, pprofile_name):
        """Create a policy profile."""
        db_session = db.get_session()
        pprofile = n1kv_models.PolicyProfile(id=id, name=pprofile_name)
        db_session.add(pprofile)
        db_session.flush()
        return pprofile

    def _get_policy_profiles(self):
        """Retrieve all policy profiles."""
        db_session = db.get_session()
        return db_session.query(n1kv_models.PolicyProfile)

    def _get_policy_profile(self, session, id):
        return n1kv_db.get_policy_profile_by_uuid(session, id)

    def _remove_policy_profile(self, pprofile_id):
        """Delete a policy profile."""
        db_session = db.get_session()
        pprofile = (db_session.query(n1kv_models.PolicyProfile).
                    filter_by(id=pprofile_id).first())
        if pprofile:
            db_session.delete(pprofile)
            db_session.flush()

    def get_policy_profile(self, context, id, fields=None):
        """
        Retrieve a policy profile for the given UUID.

        :param context: neutron api request context
        :param id: UUID representing policy profile to fetch
        :params fields: a list of strings that are valid keys in a policy
                        profile dictionary. Only these fields will be returned
        :returns: policy profile dictionary
        """
        profile = self._get_policy_profile(context.session, id)
        return self._make_policy_profile_dict(profile, fields)

    def get_policy_profiles(self, context, filters=None, fields=None):
        """
        Retrieve a list of policy profiles.

        Retrieve all policy profiles if tenant is admin. For a non-admin
        tenant, retrieve all policy profiles belonging to this tenant only.
        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        policy profile object. Values in this dictiontary are
                        an iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a policy
                        profile dictionary. Only these fields will be returned
        :returns: list of all policy profiles
        """
        return self._get_collection(context, n1kv_models.PolicyProfile,
                                    self._make_policy_profile_dict,
                                    filters=filters, fields=fields)


class PolicyProfilePlugin(PolicyProfile_db_mixin):
    """Implementation of the Cisco N1KV Policy Profile Service Plugin."""
    supported_extension_aliases = ["policy_profile"]

    def __init__(self):
        super(PolicyProfilePlugin, self).__init__()
        extensions.append_api_extensions_path(n1kv.__path__)
        # Initialize N1KV client
        self.n1kvclient = n1kv_client.Client()
        eventlet.spawn(self._poll_policy_profiles)

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
            for profile in self._get_policy_profiles():
                plugin_profiles_set.add(profile.id)
            vsm_profiles_set = set(vsm_profiles)
            # Update database if the profile sets differ.
            if vsm_profiles_set.symmetric_difference(plugin_profiles_set):
                # Add profiles in database if new profiles were created in VSM
                for pid in vsm_profiles_set.difference(plugin_profiles_set):
                    self._add_policy_profile(pid, vsm_profiles[pid])
                # Delete profiles from database if profiles were deleted in VSM
                for pid in plugin_profiles_set.difference(vsm_profiles_set):
                    self._remove_policy_profile(pid)
        except (n1kv_exc.VSMError, n1kv_exc.VSMConnectionFailed):
            with excutils.save_and_reraise_exception(reraise=False):
                LOG.warning(_LW('No policy profile populated from VSM'))

    def get_policy_profiles(self, context, filters=None, fields=None):
        """Return Cisco N1KV policy profiles."""
        return super(PolicyProfilePlugin, self).get_policy_profiles(context,
                                                                    filters,
                                                                    fields)

    def get_policy_profile(self, context, id, fields=None):
        """Return Cisco N1KV policy profile by its UUID."""
        return super(PolicyProfilePlugin, self).get_policy_profile(context,
                                                                   id,
                                                                   fields)
