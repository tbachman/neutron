# Copyright (c) 2013 OpenStack Foundation
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

from oslo.config import cfg
import sqlalchemy as sa

from neutron import manager
from neutron.api.v2 import attributes
from neutron.common import exceptions as exc
from neutron.db import model_base
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.type_driver_common import TypeDriverMixin

LOG = log.getLogger(__name__)

flat_opts = [
    cfg.ListOpt('flat_networks',
                default=[],
                help=_("List of physical_network names with which flat "
                       "networks can be created. Use * to allow flat "
                       "networks with arbitrary physical_network names."))
]

cfg.CONF.register_opts(flat_opts, "ml2_type_flat")


class FlatAllocation(model_base.BASEV2):
    """Represent persistent allocation state of a physical network.

    If a record exists for a physical network, then that physical
    network has been allocated as a flat network.
    """

    __tablename__ = 'ml2_flat_allocations'

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)
    network_id = sa.Column(sa.String(255), nullable=True)


class FlatTypeDriver(api.TypeDriver, TypeDriverMixin):
    """Manage state for flat networks with ML2.

    The FlatTypeDriver implements the 'flat' network_type. Flat
    network segments provide connectivity between VMs and other
    devices using any connected IEEE 802.1D conformant
    physical_network, without the use of VLAN tags, tunneling, or
    other segmentation mechanisms. Therefore at most one flat network
    segment can exist on each available physical_network.
    """

    def __init__(self):
        self._parse_networks(cfg.CONF.ml2_type_flat.flat_networks)

    def _parse_networks(self, entries):
        self.flat_networks = entries
        if '*' in self.flat_networks:
            LOG.info(_("Arbitrary flat physical_network names allowed"))
            self.flat_networks = None
        elif not all(self.flat_networks):
            msg = _("physical network name is empty")
            raise exc.InvalidInput(error_message=msg)
        else:
            LOG.info(_("Allowable flat physical_network names: %s"),
                     self.flat_networks)

    def get_type(self):
        return p_const.TYPE_FLAT

    def initialize(self):
        LOG.info(_("ML2 FlatTypeDriver initialization complete"))

    def allocate_static_segment(self, session, net_data):
        segments = self._process_provider_create(net_data)
        if segments:
            for segment in segments:
                self.reserve_provider_segment(session, segment)
        else:
            self.allocate_tenant_segment(session)

    def get_segment(self, context, network_id):
        LOG.debug(_("Returning segments for network %s") % network_id)
        alloc = (context.session.query(FlatAllocation).
                 filter_by(network_id=network_id).one())

        return {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                api.PHYSICAL_NETWORK: alloc.physical_network}

    def _process_provider_segment(self, segment):
        network_type = self._get_attribute(segment, provider.NETWORK_TYPE)
        physical_network = self._get_attribute(segment,
                                               provider.PHYSICAL_NETWORK)
        segmentation_id = self._get_attribute(segment,
                                              provider.SEGMENTATION_ID)

        if attributes.is_attr_set(network_type):
            segment = {api.NETWORK_TYPE: network_type,
                       api.PHYSICAL_NETWORK: physical_network,
                       api.SEGMENTATION_ID: segmentation_id}
            self.type_manager.validate_provider_segment(segment)
            return segment

        msg = _("network_type required")
        raise exc.InvalidInput(error_message=msg)

    def _process_provider_create(self, network):
        segments = []

        if any(attributes.is_attr_set(network.get(f))
               for f in (provider.NETWORK_TYPE, provider.PHYSICAL_NETWORK,
                         provider.SEGMENTATION_ID)):
            # Verify that multiprovider and provider attributes are not set
            # at the same time.
            if attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
                raise mpnet.SegmentsSetInConjunctionWithProviders()

            network_type = self._get_attribute(network, provider.NETWORK_TYPE)
            physical_network = self._get_attribute(network,
                                                   provider.PHYSICAL_NETWORK)
            segmentation_id = self._get_attribute(network,
                                                  provider.SEGMENTATION_ID)
            segments = [{provider.NETWORK_TYPE: network_type,
                         provider.PHYSICAL_NETWORK: physical_network,
                         provider.SEGMENTATION_ID: segmentation_id}]
        elif attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
            segments = network[mpnet.SEGMENTS]
        else:
            return

        return [self._process_provider_segment(s) for s in segments]

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if not physical_network:
            msg = _("physical_network required for flat provider network")
            raise exc.InvalidInput(error_message=msg)
        if self.flat_networks and physical_network not in self.flat_networks:
            msg = (_("physical_network '%s' unknown for flat provider network")
                   % physical_network)
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.iteritems():
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK]:
                msg = _("%s prohibited for flat provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        physical_network = segment[api.PHYSICAL_NETWORK]
        with session.begin(subtransactions=True):
            try:
                alloc = (session.query(FlatAllocation).
                         filter_by(physical_network=physical_network).
                         with_lockmode('update').
                         one())
                raise exc.FlatNetworkInUse(
                    physical_network=physical_network)
            except sa.orm.exc.NoResultFound:
                LOG.debug(_("Reserving flat network on physical "
                            "network %s"), physical_network)
                alloc = FlatAllocation(physical_network=physical_network)
                session.add(alloc)

    def allocate_tenant_segment(self, session):
        # Tenant flat networks are not supported.
        return

    def release_static_segment(self, session, segment):
        physical_network = segment[api.PHYSICAL_NETWORK]
        with session.begin(subtransactions=True):
            count = (session.query(FlatAllocation).
                     filter_by(physical_network=physical_network).
                     delete())
        if count:
            LOG.debug("Releasing flat network on physical network %s",
                      physical_network)
        else:
            LOG.warning(_("No flat network found on physical network %s"),
                        physical_network)
