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

"""Cisco UCS Manager Mechanism Driver - Initial

Revision ID: 20b99fd19d4f
Revises: 3bc23c072a91
Create Date: 2014-07-30 21:01:13.754637

"""

# revision identifiers, used by Alembic.
revision = '20b99fd19d4f'
down_revision = '3bc23c072a91'


from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'ml2_ucsm_port_profiles',
        sa.Column('vlan_id', sa.Integer(), nullable=False),
        sa.Column('profile_id', sa.String(length=64), nullable=False),
        sa.Column('created_on_ucs', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('vlan_id')
    )


def downgrade():
    op.drop_table('ml2_ucsm_port_profiles')
