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

import sqlalchemy as sa

from neutron.db import model_base
from neutron.db import models_v2
from neutron.plugins.common import constants


class PolicyProfile(model_base.BASEV2):

    """
    Nexus1000V Policy Profiles

    Both 'profile_id' and 'name' are populated from Nexus1000V switch.
    """
    __tablename__ = 'cisco_ml2_n1kv_policy_profiles'

    id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    name = sa.Column(sa.String(255), nullable=False)


class NetworkProfile(model_base.BASEV2, models_v2.HasId):

    """Nexus1000V Network Profiles created on the VSM."""
    __tablename__ = 'cisco_ml2_n1kv_network_profiles'

    name = sa.Column(sa.String(255), nullable=False)
    segment_type = sa.Column(sa.Enum(constants.TYPE_VLAN,
                                     constants.TYPE_VXLAN,
                                     name='segment_type'),
                             nullable=False)


class N1kvPortBinding(model_base.BASEV2):

    """Represents binding of ports to policy profile."""
    __tablename__ = 'cisco_ml2_n1kv_port_bindings'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    profile_id = sa.Column(sa.String(36),
                           sa.ForeignKey('cisco_ml2_n1kv_policy_profiles.id'),
                           nullable=False)


class N1kvNetworkBinding(model_base.BASEV2):

    """Represents binding of virtual network to network profiles."""
    __tablename__ = 'cisco_ml2_n1kv_network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    network_type = sa.Column(sa.String(32), nullable=False)
    segmentation_id = sa.Column(sa.Integer)
    profile_id = sa.Column(sa.String(36),
                           sa.ForeignKey('cisco_ml2_n1kv_network_profiles.id'),
                           nullable=False)
