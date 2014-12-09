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

import netaddr
import re

from sqlalchemy.orm import exc

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
import neutron.db.api as db
from neutron.db import common_db_mixin as base_db
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.cisco import n1kv
from neutron.plugins.ml2.drivers.cisco.n1kv import config # noqa
from neutron.plugins.ml2.drivers.cisco.n1kv import constants as n1kv_const
from neutron.plugins.ml2.drivers.cisco.n1kv import exceptions as n1kv_exc
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_client
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_db
from neutron.plugins.ml2.drivers.cisco.n1kv import n1kv_models
from neutron.plugins.ml2.drivers.cisco.n1kv import network_profile

LOG = logging.getLogger(__name__)


class NetworkProfile_db_mixin(network_profile.NetworkProfilePluginBase,
                              base_db.CommonDbMixin):
    """Network Profile Mixin class."""

    def _make_network_profile_dict(self, network_profile, fields=None):
        res = {"id": network_profile["id"],
               "name": network_profile["name"],
               "segment_type": network_profile["segment_type"],
               "sub_type": network_profile["sub_type"],
               "segment_range": network_profile["segment_range"],
               "multicast_ip_index": network_profile["multicast_ip_index"],
               "multicast_ip_range": network_profile["multicast_ip_range"],
               "physical_network": network_profile["physical_network"]}
        return self._fields(res, fields)

    def _get_network_collection_for_tenant(self, db_session, model, tenant_id):
        net_profile_ids = (db_session.query(n1kv_models.ProfileBinding.
                                            profile_id).
                           filter_by(tenant_id=tenant_id).
                           filter_by(profile_type="network"))
        network_profiles = (db_session.query(model).filter(model.id.in_(
            pid[0] for pid in net_profile_ids)))
        return [self._make_network_profile_dict(p) for p in network_profiles]

    def _add_network_profile(self, network_profile, db_session=None):
        """Create a network profile."""
        db_session = db_session or db.get_session()
        with db_session.begin(subtransactions=True):
            kwargs = {"name": network_profile["name"],
                      "segment_type": network_profile["segment_type"]}
            if network_profile["segment_type"] == p_const.TYPE_VLAN:
                kwargs["physical_network"] = network_profile["physical_network"]
                kwargs["segment_range"] = network_profile["segment_range"]
            elif network_profile["segment_type"] == n1kv_const.TYPE_OVERLAY:
                kwargs["multicast_ip_index"] = 0
                kwargs["multicast_ip_range"] = network_profile[
                    "multicast_ip_range"]
                kwargs["segment_range"] = network_profile["segment_range"]
                kwargs["sub_type"] = network_profile["sub_type"]
            elif network_profile["segment_type"] == n1kv_const.TYPE_TRUNK:
                kwargs["sub_type"] = network_profile["sub_type"]
            net_profile = n1kv_models.NetworkProfile(**kwargs)
            db_session.add(net_profile)
            db_session.flush()
            return net_profile

    def _get_network_profile(self, db_session, id):
        try:
            return (db_session.query(n1kv_models.NetworkProfile).
                    filter_by(id=id).one())
        except exc.NoResultFound:
            raise n1kv_exc.NetworkProfileNotFound(profile=id)

    def _get_network_profiles(self, db_session=None, physical_network=None):
        """
        Retrieve all network profiles.

        Get Network Profiles on a particular physical network, if physical
        network is specified. If no physical network is specified, return
        all network profiles.
        """
        db_session = db_session or db.get_session()
        if physical_network:
            return (db_session.query(n1kv_models.NetworkProfile).
                    filter_by(physical_network=physical_network))
        return db_session.query(n1kv_models.NetworkProfile)

    def _remove_network_profile(self, nprofile_id, db_session=None):
        """Delete a network profile."""
        db_session = db_session or db.get_session()
        nprofile = (db_session.query(n1kv_models.NetworkProfile).
                    filter_by(id=nprofile_id).first())
        if nprofile:
            db_session.delete(nprofile)
            db_session.flush()
        return nprofile

    def _segment_in_use(self, db_session, network_profile):
        """Verify whether a segment is allocated for given network profile."""
        with db_session.begin(subtransactions=True):
            return (db_session.query(n1kv_models.N1kvNetworkBinding).
                    filter_by(profile_id=network_profile['id'])).first()

    def _validate_network_profile_args(self, context, p):
        """
        Validate completeness of Nexus1000V network profile arguments.

        :param context: neutron api request context
        :param p: network profile object
        """
        self._validate_network_profile(p)
        segment_type = p['segment_type'].lower()
        if segment_type != n1kv_const.TYPE_TRUNK:
            self._validate_segment_range_uniqueness(context, p)

    def _validate_network_profile(self, net_p):
        """
        Validate completeness of a network profile arguments.

        :param net_p: network profile object
        """
        if net_p["segment_type"] == "":
            msg = _("Arguments segment_type missing"
                    " for network profile")
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)
        segment_type = net_p["segment_type"].lower()
        if segment_type not in [p_const.TYPE_VLAN,
                                n1kv_const.TYPE_OVERLAY,
                                n1kv_const.TYPE_TRUNK]:
            msg = _("segment_type should either be vlan, overlay, "
                    "or trunk")
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)
        if segment_type == p_const.TYPE_VLAN:
            if "physical_network" not in net_p:
                msg = _("Argument physical_network missing "
                        "for network profile")
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
        if segment_type == n1kv_const.TYPE_TRUNK:
            if net_p["segment_range"]:
                msg = _("segment_range not required for trunk")
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
        if segment_type in [n1kv_const.TYPE_TRUNK,
                            n1kv_const.TYPE_OVERLAY]:
            if not attributes.is_attr_set(net_p.get("sub_type")):
                msg = _("Argument sub_type missing "
                        "for network profile")
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
        if segment_type in [p_const.TYPE_VLAN,
                            n1kv_const.TYPE_OVERLAY]:
            if "segment_range" not in net_p:
                msg = _("Argument segment_range missing "
                        "for network profile")
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
            self._validate_segment_range(net_p)
        if segment_type == n1kv_const.TYPE_OVERLAY:
            if net_p['sub_type'] != n1kv_const.MODE_NATIVE_VXLAN:
                net_p['multicast_ip_range'] = '0.0.0.0'
            else:
                multicast_ip_range = net_p.get("multicast_ip_range")
                if not attributes.is_attr_set(multicast_ip_range):
                    msg = _("Argument multicast_ip_range missing"
                            " for VXLAN multicast network profile")
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                self._validate_multicast_ip_range(net_p)
        else:
            net_p['multicast_ip_range'] = '0.0.0.0'

    def _validate_segment_range(self, network_profile):
        """
        Validate segment range values.

        :param network_profile: network profile object
        """
        if not re.match(r"(\d+)\-(\d+)", network_profile["segment_range"]):
            msg = _("Invalid segment range. example range: 500-550")
            raise n_exc.InvalidInput(error_message=msg)

    def _validate_multicast_ip_range(self, network_profile):
        """
        Validate multicast ip range values.

        :param network_profile: network profile object
        """
        try:
            min_ip, max_ip = (network_profile
                              ['multicast_ip_range'].split('-', 1))
        except ValueError:
            msg = _("Invalid multicast ip address range. "
                    "example range: 224.1.1.1-224.1.1.10")
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)
        for ip in [min_ip, max_ip]:
            try:
                if not netaddr.IPAddress(ip).is_multicast():
                    msg = _("%s is not a valid multicast ip address") % ip
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                if netaddr.IPAddress(ip) <= netaddr.IPAddress('224.0.0.255'):
                    msg = _("%s is reserved multicast ip address") % ip
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
            except netaddr.AddrFormatError:
                msg = _("%s is not a valid ip address") % ip
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
        if netaddr.IPAddress(min_ip) > netaddr.IPAddress(max_ip):
            msg = (_("Invalid multicast IP range '%(min_ip)s-%(max_ip)s':"
                     " Range should be from low address to high address") %
                   {'min_ip': min_ip, 'max_ip': max_ip})
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)

    def _validate_segment_range_uniqueness(self, context, net_p, id=None):
        """
        Validate that segment range doesn't overlap.

        :param context: neutron api request context
        :param net_p: network profile dictionary
        :param id: UUID representing the network profile being updated
        """
        segment_type = net_p["segment_type"].lower()
        seg_min, seg_max = self._get_segment_range(net_p['segment_range'])
        if segment_type == p_const.TYPE_VLAN:
            if not ((seg_min <= seg_max) and
                    ((seg_min in range(constants.MIN_VLAN_TAG,
                                       n1kv_const.NEXUS_VLAN_RESERVED_MIN) and
                      seg_max in range(constants.MIN_VLAN_TAG,
                                       n1kv_const.NEXUS_VLAN_RESERVED_MIN)) or
                     (seg_min in range(n1kv_const.NEXUS_VLAN_RESERVED_MAX + 1,
                                       constants.MAX_VLAN_TAG) and
                      seg_max in range(n1kv_const.NEXUS_VLAN_RESERVED_MAX + 1,
                                       constants.MAX_VLAN_TAG)))):
                msg = (_("Segment range is invalid, select from "
                         "%(min)s-%(nmin)s, %(nmax)s-%(max)s") %
                       {"min": constants.MIN_VLAN_TAG,
                        "nmin": n1kv_const.NEXUS_VLAN_RESERVED_MIN - 1,
                        "nmax": n1kv_const.NEXUS_VLAN_RESERVED_MAX + 1,
                        "max": constants.MAX_VLAN_TAG - 1})
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
            profiles = self._get_network_profiles(
                db_session=context.session,
                physical_network=net_p["physical_network"]
            )
        elif segment_type in [n1kv_const.TYPE_OVERLAY,
                              n1kv_const.TYPE_TRUNK]:
            if (seg_min > seg_max or
                seg_min < n1kv_const.NEXUS_VXLAN_MIN or
                seg_max > n1kv_const.NEXUS_VXLAN_MAX):
                msg = (_("segment range is invalid. Valid range is : "
                         "%(min)s-%(max)s") %
                       {"min": n1kv_const.NEXUS_VXLAN_MIN,
                        "max": n1kv_const.NEXUS_VXLAN_MAX})
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
            profiles = self._get_network_profiles(db_session=context.session)
        if profiles:
            for profile in profiles:
                if id and profile.id == id:
                    continue
                name = profile.name
                segment_range = profile.segment_range
                if net_p["name"] == name:
                    msg = (_("NetworkProfile name %s already exists"),
                           net_p["name"])
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                seg_min, seg_max = self._get_segment_range(
                    net_p["segment_range"])
                profile_seg_min, profile_seg_max = self._get_segment_range(
                    segment_range)
                if ((profile_seg_min <= seg_min <= profile_seg_max) or
                    (profile_seg_min <= seg_max <= profile_seg_max) or
                    ((seg_min <= profile_seg_min) and
                     (seg_max >= profile_seg_max))):
                    msg = _("Segment range overlaps with another profile")
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)

    def _get_segment_range(self, data):
        return (int(seg) for seg in data.split("-")[:2])

    def _sync_vlan_allocations(self, db_session, net_p):
        """
        Synchronize vlan_allocations table with configured VLAN ranges.

        Sync the network profile range with the vlan_allocations table for each
        physical network.
        :param db_session: database session
        :param net_p: network profile dictionary
        """
        with db_session.begin(subtransactions=True):
            seg_min, seg_max = self._get_segment_range(net_p.segment_range)
            for vlan_id in range(seg_min, seg_max + 1):
                try:
                    self._get_vlan_allocation(db_session,
                                              net_p['physical_network'],
                                              vlan_id)
                except n1kv_exc.VlanIDNotFound:
                    alloc = n1kv_models.N1kvVlanAllocation(
                        physical_network=net_p['physical_network'],
                        vlan_id=vlan_id,
                        network_profile_id=net_p['id'])
                    db_session.add(alloc)

    def _get_vlan_allocation(self, db_session, physical_network, vlan_id):
        """
        Retrieve vlan allocation.

        :param db_session: database session
        :param physical network: string name for the physical network
        :param vlan_id: integer representing the VLAN ID.
        :returns: allocation object for given physical network and VLAN ID
        """
        try:
            return (db_session.query(n1kv_models.N1kvVlanAllocation).
                    filter_by(physical_network=physical_network,
                              vlan_id=vlan_id).one())
        except exc.NoResultFound:
            raise n1kv_exc.VlanIDNotFound(vlan_id=vlan_id)

    def _sync_vxlan_allocations(self, db_session, net_p):
        """
        Synchronize vxlan_allocations table with configured vxlan ranges.

        :param db_session: database session
        :param net_p: network profile dictionary
        """
        seg_min, seg_max = self._get_segment_range(net_p.segment_range)
        if seg_max + 1 - seg_min > n1kv_const.MAX_VXLAN_RANGE:
            msg = (_("Unreasonable vxlan ID range %(vxlan_min)s - %(vxlan_max)s"),
                   {"vxlan_min": seg_min, "vxlan_max": seg_max})
            raise n_exc.InvalidInput(error_message=msg)
        with db_session.begin(subtransactions=True):
            for vxlan_id in range(seg_min, seg_max + 1):
                try:
                    self._get_vxlan_allocation(db_session, vxlan_id)
                except n1kv_exc.VxlanIDNotFound:
                    alloc = n1kv_models.N1kvVxlanAllocation(
                        network_profile_id=net_p['id'], vxlan_id=vxlan_id)
                    db_session.add(alloc)

    def _get_vxlan_allocation(self, db_session, vxlan_id):
        """
        Retrieve VXLAN allocation for the given VXLAN ID.

        :param db_session: database session
        :param vxlan_id: integer value representing the segmentation ID
        :returns: allocation object
        """
        try:
            return (db_session.query(n1kv_models.N1kvVxlanAllocation).
                    filter_by(vxlan_id=vxlan_id).one())
        except exc.NoResultFound:
            raise n1kv_exc.VxlanIDNotFound(vxlan_id=vxlan_id)

    def _create_profile_binding(self, db_session, tenant_id, profile_id):
        """Create Network Profile association with a tenant."""
        db_session = db_session or db.get_session()
        if self._profile_binding_exists(db_session,
                                        tenant_id,
                                        profile_id):
            return self._get_profile_binding(db_session, tenant_id, profile_id)

        with db_session.begin(subtransactions=True):
            binding = n1kv_models.ProfileBinding(profile_type='network',
                                                 profile_id=profile_id,
                                                 tenant_id=tenant_id)
            db_session.add(binding)
            return binding

    def _profile_binding_exists(self, db_session, tenant_id, profile_id):
        """Check if the profile-tenant binding exists."""
        db_session = db_session or db.get_session()
        return (db_session.query(n1kv_models.ProfileBinding).
                filter_by(tenant_id=tenant_id, profile_id=profile_id,
                          profile_type='network').first())

    def _get_profile_binding(self, db_session, tenant_id, profile_id):
        """Get Network Profile - Tenant binding."""
        try:
            return (db_session.query(n1kv_models.ProfileBinding).filter_by(
                tenant_id=tenant_id, profile_id=profile_id).one())
        except exc.NoResultFound:
            raise n1kv_exc.ProfileTenantBindingNotFound(profile_id=profile_id)

    def get_network_profile(self, context, id, fields=None):
        """
        Retrieve a network profile for the given UUID.

        :param context: neutron api request context
        :param id: UUID representing network profile to fetch
        :params fields: a list of strings that are valid keys in a network
                        profile dictionary. Only these fields will be returned
        :returns: network profile dictionary
        """
        profile = self._get_network_profile(context.session, id)
        return self._make_network_profile_dict(profile, fields)

    def get_network_profiles(self, context, filters=None, fields=None):
        """
        Retrieve a list of network profiles.

        Retrieve all network profiles if tenant is admin. For a non-admin
        tenant, retrieve all network profiles belonging to this tenant only.
        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        network profile object. Values in this dictiontary are
                        an iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a network
                        profile dictionary. Only these fields will be returned
        :returns: list of all network profiles
        """
        if context.is_admin:
            return self._get_collection(context, n1kv_models.NetworkProfile,
                                        self._make_network_profile_dict,
                                        filters=filters, fields=fields)
        return self._get_network_collection_for_tenant(context.session,
                                                       n1kv_models.
                                                       NetworkProfile,
                                                       context.tenant_id)

    def create_network_profile(self, context, network_profile):
        """
        Create a network profile.

        :param context: neutron api request context
        :param network_profile: network profile dictionary
        :returns: network profile dictionary
        """
        p = network_profile["network_profile"]
        self._validate_network_profile_args(context, p)
        with context.session.begin(subtransactions=True):
            net_profile = self._add_network_profile(db_session=context.session,
                                                    network_profile=p)
            if net_profile.segment_type == p_const.TYPE_VLAN:
                self._sync_vlan_allocations(context.session, net_profile)
            elif net_profile.segment_type == n1kv_const.TYPE_OVERLAY:
                self._sync_vxlan_allocations(context.session, net_profile)
            self._create_profile_binding(context.session,
                                         context.tenant_id,
                                         net_profile.id)
            if p.get(n1kv_const.ADD_TENANTS):
                for tenant in p[n1kv_const.ADD_TENANTS]:
                    self._create_profile_binding(context.session,
                                                 tenant,
                                                 net_profile.id)
        return self._make_network_profile_dict(net_profile)

    def delete_network_profile(self, context, id):
        """
        Delete a network profile.

        :param context: neutron api request context
        :param id: UUID representing network profile to delete
        :returns: deleted network profile dictionary
        """
        # Check whether the network profile is in use.
        if self._segment_in_use(context.session,
                                self._get_network_profile(context.session,
                                                          id)):
            raise n1kv_exc.NetworkProfileInUse(profile=id)
        # Delete and return the network profile if it is not in use.
        nprofile = self._remove_network_profile(id, context.session)
        return self._make_network_profile_dict(nprofile)

    def update_network_profile(self, context, id, network_profile):
        pass


class NetworkProfilePlugin(NetworkProfile_db_mixin):
    """Implementation of the Cisco N1KV Network Profile Service Plugin."""
    supported_extension_aliases = ["network_profile"]

    def __init__(self):
        super(NetworkProfilePlugin, self).__init__()
        extensions.append_api_extensions_path(n1kv.__path__)
        # Initialize N1KV client
        self.n1kvclient = n1kv_client.Client()

    def get_network_profiles(self, context, filters=None, fields=None):
        """Return Cisco N1KV network profiles."""
        return super(NetworkProfilePlugin, self).get_network_profiles(context,
                                                                      filters,
                                                                      fields)

    def get_network_profile(self, context, id, fields=None):
        """Return Cisco N1KV network profile by its UUID."""
        return super(NetworkProfilePlugin, self).get_network_profile(context,
                                                                     id,
                                                                     fields)

    def create_network_profile(self, context, network_profile):
        """
        Create a network profile.

        :param context: neutron api request context
        :param network_profile: network profile dictionary
        :returns: network profile object
        """
        with context.session.begin(subtransactions=True):
            net_p = super(NetworkProfilePlugin,
                          self).create_network_profile(context,
                                                       network_profile)
        try:
            # Create a network profile on the VSM
            self.n1kvclient.create_network_segment_pool(net_p)
        # Catch any exception here and cleanup if so
        except (n1kv_exc.VSMConnectionFailed, n1kv_exc.VSMError):
            with excutils.save_and_reraise_exception():
                super(NetworkProfilePlugin,
                      self).delete_network_profile(context, id)
        return net_p

    def delete_network_profile(self, context, id):
        """
        Delete a network profile.

        :param context: neutron api request context
        :param id: UUID of the network profile to delete
        :returns: deleted network profile object
        """
        with context.session.begin(subtransactions=True):
            net_p = super(NetworkProfilePlugin,
                          self).delete_network_profile(context, id)
        self.n1kvclient.delete_network_segment_pool(id)

    def update_network_profile(self, context, id, network_profile):
        """
        Update a network profile.

        :param context: neutron api request context
        :param net_profile_id: UUID of the network profile to update
        :param network_profile: dictionary containing network profile object
        """
        session = context.session
        with session.begin(subtransactions=True):
            net_p = (super(NetworkProfilePlugin, self).
                     update_network_profile(context,
                                            id,
                                            network_profile))
        # Update and handle exception on VSM
