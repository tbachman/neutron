# vim: tabstop=10 shiftwidth=4 softtabstop=4
#
# Copyright 2014, Paul Michali, Cisco Systems, Inc.
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

import sqlalchemy as sa

from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

# Note: Artificially limit these to reduce mapping table size and performance
# Tunnel can be 0..7FFFFFFF, IKE policy can be 1..10000
MAX_CSR_TUNNELS = 2048
MAX_CSR_IKE_POLICIES = 256


class IdentifierMap(model_base.BASEV2, models_v2.HasTenant):

    """Maps OpenStack IDs to compatible numbers for Cisco CSR."""

    __tablename__ = 'csr_identifier_map'

    ipsec_site_conn_id = sa.Column(sa.String(64), primary_key=True)
    ipsec_tunnel_id = sa.Column(sa.Integer, nullable=False)
    ike_policy_id = sa.Column(sa.Integer, nullable=False)


def get_next_available_tunnel_id(session):
    """Find first unused int from 0..2^32-1 for tunnel ID."""
    rows = session.query(IdentifierMap.ipsec_tunnel_id)
    used_ids = set([row[0] for row in rows])
    all_ids = set(range(MAX_CSR_TUNNELS))
    available_ids = all_ids - used_ids
    if not available_ids:
        msg = _("No available IDs from 0..%d") % (MAX_CSR_TUNNELS - 1)
        LOG.error(msg)
        raise IndexError(msg)
    return available_ids.pop()

# TODO(pcm): Remove
def get_tunnels(session):
    return session.query(IdentifierMap).all()

def get_or_create_csr_ike_policy_id(context):
    """Find ID used by other tunnels or create next avail one from 0..10K."""
    return 2


def create_tunnel_mapping(context, conn_info):
    """Create Cisco CSR IDs, using mapping table and OpenStack UUIDs."""
    conn_id = conn_info['id']
    # TOTO(pcm) Do we need to do ~_get_tenant_id_for_create()?
    tenant_id = conn_info['tenant_id']
    with context.session.begin(subtransactions=True):
        tunnel_id = get_next_available_tunnel_id(context.session)
        ike_policy_id = get_or_create_csr_ike_policy_id(context)
        map_entry = IdentifierMap(tenant_id=tenant_id,
                                  ipsec_site_conn_id=conn_id,
                                  ipsec_tunnel_id=tunnel_id,
                                  ike_policy_id=ike_policy_id)
        context.session.add(map_entry)
        LOG.debug(_("Mapped %(conn_id)s to Tunnel%(tunnel_id)d using IKE "
                    "policy ID %(ike_id)d"), {'conn_id': conn_id,
                                              'tunnel_id': tunnel_id,
                                              'ike_id': ike_policy_id})
    return tunnel_id, ike_policy_id


def delete_tunnel_mapping(context, conn_info):
    with context.session.begin(subtransactions=True):
        sess_qry = context.session.query(IdentifierMap)
        sess_qry.filter_by(ipsec_site_conn_id=conn_info['id']).delete()
