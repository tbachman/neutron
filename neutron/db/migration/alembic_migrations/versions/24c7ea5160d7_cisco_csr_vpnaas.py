# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 OpenStack Foundation
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

"""Cisco CSR VPNaaS

Revision ID: 24c7ea5160d7
Revises: havana
Create Date: 2014-02-03 13:06:50.407601

"""

# revision identifiers, used by Alembic.
revision = '24c7ea5160d7'
down_revision = 'havana'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = [
    'neutron.services.vpn.plugin.VPNDriverPlugin',
]

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create.table(
        'csr_identifier_map',
        sa.Column('ipsec_site_conn_id', sa.String(length=64), primary_key=True),
        sa.Column('ipsec_tunnel_id', sa.Integer(), nullable=False),
        sa.Column('ike_policy_id', sa.Integer(), nullable=False))

def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    os.drop_table('csr_identifier_map')
