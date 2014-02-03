# vim: tabstop=10 shiftwidth=4 softtabstop=4
#
# Copyright 2013, Paul Michali, Cisco Systems, Inc.
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


def get_next_available_tunnel_id(context, conn_info):
    with context.session.begin(subtransactions=True):
        used_ids = context.session.query(IdentifierMap.ipsec_tunnel_id).all()
        all_ids = set(range(MAX_CSR_TUNNELS))
        available_ids = all_ids - set(used_ids)
        if not available_ids:
            msg = _("No available IDs from 0..%d") % (MAX_CSR_TUNNELS - 1)
            LOG.error(msg)
            raise IndexError(msg)
        tunnel_id = available_ids.pop()
        map_entry = IdentifierMap(ipsec_site_conn_id=conn_info['id'],
                                  ipsec_tunnel_id=tunnel_id,
                                  ike_policy_id=2)  # Hardcode for now
        context.session.add(map_entry)
    LOG.debug(_("Mapped %(conn_id)s to Tunnel%(tunnel_id)d"),
              {'conn_id': conn_info['id'], 'tunnel_id': tunnel_id})
    return tunnel_id

def delete_tunnel_id_mapping(context, conn_info):
    with context.session.begin(subtransactions=True):
        sess_qry = context.session.query(IdentifierMap)
        sess_qry.filter_by(ipsec_site_conn_id=conn_info['id']).delete()
