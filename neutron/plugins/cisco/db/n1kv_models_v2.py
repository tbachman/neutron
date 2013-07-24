# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cisco Systems, Inc.
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

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Enum
from sqlalchemy.orm import exc
from sqlalchemy.orm import object_mapper

from neutron.db import model_base
from neutron.db.models_v2 import HasId
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.common import cisco_exceptions


LOG = logging.getLogger(__name__)
SEGMENT_TYPE_VLAN = 'vlan'
SEGMENT_TYPE_VXLAN = 'vxlan'
SEGMENT_TYPE = Enum(SEGMENT_TYPE_VLAN, SEGMENT_TYPE_VXLAN)
PROFILE_TYPE = Enum(cisco_constants.NETWORK, cisco_constants.POLICY)
# use this to indicate that tenant_id was not yet set
TENANT_ID_NOT_SET = '01020304-0506-0708-0901-020304050607'


class N1kvVlanAllocation(model_base.BASEV2):

    """Represents allocation state of vlan_id on physical network."""
    __tablename__ = 'n1kv_vlan_allocations'

    physical_network = Column(String(64), nullable=False, primary_key=True)
    vlan_id = Column(Integer, nullable=False, primary_key=True,
                     autoincrement=False)
    allocated = Column(Boolean, nullable=False, default=False)


class N1kvVxlanAllocation(model_base.BASEV2):

    """Represents allocation state of vxlan_id."""
    __tablename__ = 'n1kv_vxlan_allocations'

    vxlan_id = Column(Integer, nullable=False, primary_key=True,
                      autoincrement=False)
    allocated = Column(Boolean, nullable=False, default=False)


class N1kvPortBinding(model_base.BASEV2):

    """Represents binding of ports to policy profile."""
    __tablename__ = 'n1kv_port_bindings'

    port_id = Column(String(36),
                     ForeignKey('ports.id', ondelete="CASCADE"),
                     primary_key=True)
    profile_id = Column(String(36))


class N1kvNetworkBinding(model_base.BASEV2):

    """Represents binding of virtual network to physical realization."""
    __tablename__ = 'n1kv_network_bindings'

    network_id = Column(String(36),
                        ForeignKey('networks.id', ondelete="CASCADE"),
                        primary_key=True)
    # 'vxlan', 'vlan'
    network_type = Column(String(32), nullable=False)
    physical_network = Column(String(64))
    segmentation_id = Column(Integer)  # vxlan_id or vlan_id
    multicast_ip = Column(String(32))  # multicast ip
    profile_id = Column(String(36))  # n1kv profile id


class L2NetworkBase(object):

    """Base class for L2Network Models."""
    #__table_args__ = {'mysql_engine': 'InnoDB'}

    def __setitem__(self, key, value):
        """Internal Dict set method."""
        setattr(self, key, value)

    def __getitem__(self, key):
        """Internal Dict get method."""
        return getattr(self, key)

    def get(self, key, default=None):
        """Dict get method."""
        return getattr(self, key, default)

    def __iter__(self):
        """Iterate over table columns."""
        self._i = iter(object_mapper(self).columns)
        return self

    def next(self):
        """Next method for the iterator"""
        n = self._i.next().name
        return n, getattr(self, n)

    def update(self, values):
        """Make the model object behave like a dict."""
        for k, v in values.iteritems():
            setattr(self, k, v)

    def iteritems(self):
        """

        Make the model object behave like a dict
        Includes attributes from joins.

        """
        local = dict(self)
        joined = dict([(k, v) for k, v in self.__dict__.iteritems()
                       if not k[0] == '_'])
        local.update(joined)
        return local.iteritems()


class N1kVmNetwork(model_base.BASEV2):

    """Represents VM Network information."""
    __tablename__ = 'vmnetwork'

    name = Column(String(80), primary_key=True)
    profile_id = Column(String(36))
    network_id = Column(String(36))
    port_count = Column(Integer)


class NetworkProfile(model_base.BASEV2, HasId):

    """
    Nexus1000V Network Profiles

        segment_type - VLAN, VXLAN
        segment_range - '<integer>-<integer>'
        multicast_ip_index - <integer>
        multicast_ip_range - '<ip>-<ip>'
        physical_network - Name for the physical network
    """
    __tablename__ = 'network_profiles'

    name = Column(String(255))
    segment_type = Column(SEGMENT_TYPE, nullable=False)
    segment_range = Column(String(255))
    multicast_ip_index = Column(Integer, default=0)
    multicast_ip_range = Column(String(255))
    physical_network = Column(String(255))

    def get_segment_range(self, session):
        """Get the segment range min and max for a network profile."""
        with session.begin(subtransactions=True):
            # Sort the range to ensure min, max is in order
            seg_min, seg_max = sorted(map(int, self.segment_range.split('-')))
            LOG.debug(_("seg_min %(seg_min)s, seg_max %(seg_max)s"),
                      {'seg_min': seg_min, 'seg_max': seg_max})
            return seg_min, seg_max

    def get_multicast_ip(self, session):
        "Returns a multicast ip from the defined pool."
        # Round robin multicast ip allocation
        with session.begin(subtransactions=True):
            try:
                min_ip, max_ip = self._get_multicast_ip_range()
                min_addr = int(min_ip.split('.')[3])
                max_addr = int(max_ip.split('.')[3])
                addr_list = list(xrange(min_addr, max_addr + 1))

                mul_ip = min_ip.split('.')
                mul_ip[3] = str(addr_list[self.multicast_ip_index])

                self.multicast_ip_index += 1
                if self.multicast_ip_index == len(addr_list):
                    self.multicast_ip_index = 0
                mul_ip_str = '.'.join(mul_ip)
                return mul_ip_str

            except exc.NoResultFound:
                raise cisco_exceptions.NetworkProfileIdNotFound(profile_id=id)

    def _get_multicast_ip_range(self):
        # Assumption: ip range belongs to the same subnet
        # Assumption: ip range is already sorted
        # min_ip, max_ip = sorted(self.multicast_ip_range.split('-'))
        min_ip, max_ip = self.multicast_ip_range.split('-')
        return (min_ip, max_ip)


class PolicyProfile(model_base.BASEV2):

    """
    Nexus1000V Network Profiles

        Both 'id' and 'name' are coming from Nexus1000V switch
    """
    __tablename__ = 'policy_profiles'

    id = Column(String(36), primary_key=True)
    name = Column(String(255))


class ProfileBinding(model_base.BASEV2):

    """
    Represents a binding of Network Profile
    or Policy Profile to tenant_id
    """
    __tablename__ = 'profile_bindings'

    profile_type = Column(PROFILE_TYPE)
    tenant_id = Column(String(36), primary_key=True, default=TENANT_ID_NOT_SET)
    profile_id = Column(String(36), primary_key=True)
