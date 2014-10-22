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

"""cisco_ml2_nexus_vxlan

Revision ID: 3bc23c072a91
Revises: 208b451f0e97
Create Date: 2014-09-11 19:50:55.964739

"""

# revision identifiers, used by Alembic.
revision = '3bc23c072a91'
down_revision = '208b451f0e97'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'cisco_ml2_nexus_nve',
        sa.Column('vni', sa.Integer(), nullable=False),
        sa.Column('switch_ip', sa.String(length=255), nullable=True),
        sa.Column('mcast_group', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('vni', 'switch_ip'))

    op.add_column(
        'cisco_ml2_nexusport_bindings',
        sa.Column('vni', sa.Integer(), nullable=True))


def downgrade():
    op.drop_column('cisco_ml2_nexusport_bindings', 'vni')

    op.drop_table('cisco_ml2_nexus_nve')
