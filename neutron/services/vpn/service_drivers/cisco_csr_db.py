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
from sqlalchemy.orm import exc as sql_exc

from neutron.common import exceptions
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db.vpn import vpn_db
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

# Note: Artificially limit these to reduce mapping table size and performance
# Tunnel can be 0..7FFFFFFF, IKE policy can be 1..10000
MAX_CSR_TUNNELS = 10000
MAX_CSR_IKE_POLICIES = 2000


class CsrInternalError(exceptions.NeutronException):
    message = _("Fatal - %(reason)s")


class IdentifierMap(model_base.BASEV2, models_v2.HasTenant):

    """Maps OpenStack IDs to compatible numbers for Cisco CSR."""

    __tablename__ = 'csr_identifier_map'

    ipsec_site_conn_id = sa.Column(sa.String(64), primary_key=True)
    csr_tunnel_id = sa.Column(sa.Integer, nullable=False)
    csr_ike_policy_id = sa.Column(sa.Integer, nullable=False)


def get_next_available_id(session, table_field, id_type, min_value, max_value):
    """Find first unused id for the specified field in IdentifierMap table.

    As entries are removed, find the first "hole" and return that as the
    next available ID. To improve performance, artificially limit
    the number of entries to a smaller range. Currently, these IDs are
    globally unique. Could enhance in the future to be unique per router
    (CSR).
    """
    rows = session.query(table_field)
    used_ids = set([row[0] for row in rows])
    all_ids = set(range(min_value, max_value))
    available_ids = all_ids - used_ids
    if not available_ids:
        msg = _("No available Cisco CSR %(type)s IDs from "
                "%(min)d..%(max)d") % {'type': id_type,
                                       'min': min_value,
                                       'max': max_value - 1}
        LOG.error(msg)
        raise IndexError(msg)
    return available_ids.pop()


def get_next_available_tunnel_id(session):
    """Find first available tunnel ID from 0..MAX_CSR_TUNNELS-1."""
    return get_next_available_id(session, IdentifierMap.csr_tunnel_id,
                                 'Tunnel', 0, MAX_CSR_TUNNELS)


def get_next_available_ike_policy_id(session):
    """Find first available IKE Policy ID from 1..MAX_CSR_IKE_POLICIES."""
    return get_next_available_id(session, IdentifierMap.csr_ike_policy_id,
                                 'IKE Policy', 1, MAX_CSR_IKE_POLICIES + 1)


def find_connection_using_ike_policy(ike_policy_id, conn_id, session):
    """Return another connection that uses same IKE policy ID."""
    qry = session.query(vpn_db.IPsecSiteConnection.ikepolicy_id)
    return qry.filter(vpn_db.IPsecSiteConnection.ikepolicy_id == ike_policy_id,
                      vpn_db.IPsecSiteConnection.id != conn_id).first()


def lookup_ike_policy_id_for(conn_id, session):
    """Obtain existing Cisco CSR IKE policy ID from another connection."""
    try:
        query = session.query(IdentifierMap.csr_ike_policy_id)
        return query.filter_by(ipsec_site_conn_id=conn_id).one()[0]
    except sql_exc.NoResultFound:
        msg = _("Database inconsistency between IPSec connection and "
                "Cisco CSR mapping table")
        raise CsrInternalError(reason=msg)


def determine_csr_ike_policy_id(ike_policy_id, conn_id, session):
    """Use existing, or reserve a new IKE policy ID for Cisco CSR."""

    conn_using_same_ike_id = find_connection_using_ike_policy(ike_policy_id,
                                                              conn_id,
                                                              session)
    if conn_using_same_ike_id:
        csr_ike_id = lookup_ike_policy_id_for(conn_using_same_ike_id, session)
    else:
        csr_ike_id = get_next_available_ike_policy_id(session)
    return csr_ike_id


def create_tunnel_mapping(context, conn_info):
    """Create Cisco CSR IDs, using mapping table and OpenStack UUIDs."""
    conn_id = conn_info['id']
    ike_policy_id = conn_info['ikepolicy_id']
    # TOTO(pcm) Do we need to do ~_get_tenant_id_for_create() for tenant ID?
    tenant_id = conn_info['tenant_id']
    with context.session.begin(subtransactions=True):
        csr_tunnel_id = get_next_available_tunnel_id(context.session)
        csr_ike_id = determine_csr_ike_policy_id(ike_policy_id, conn_id,
                                                 context.session)
        map_entry = IdentifierMap(tenant_id=tenant_id,
                                  ipsec_site_conn_id=conn_id,
                                  csr_tunnel_id=csr_tunnel_id,
                                  csr_ike_policy_id=csr_ike_id)
        context.session.add(map_entry)
        LOG.debug(_("Mapped %(conn_id)s to Tunnel%(tunnel_id)d using IKE "
                    "policy ID %(ike_id)d"), {'conn_id': conn_id,
                                              'tunnel_id': csr_tunnel_id,
                                              'ike_id': csr_ike_id})
    return csr_tunnel_id, csr_ike_id


def delete_tunnel_mapping(context, conn_info):
    with context.session.begin(subtransactions=True):
        sess_qry = context.session.query(IdentifierMap)
        sess_qry.filter_by(ipsec_site_conn_id=conn_info['id']).delete()
