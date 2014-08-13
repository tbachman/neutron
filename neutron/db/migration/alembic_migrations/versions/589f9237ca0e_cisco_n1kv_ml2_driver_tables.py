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

"""Cisco N1kv ML2 driver tables

Revision ID: 589f9237ca0e
Revises: 2026156eab2f
Create Date: 2014-08-13 13:31:43.537460

"""

# revision identifiers, used by Alembic.
revision = '589f9237ca0e'
down_revision = '2026156eab2f'

migration_for_plugins = [
    'neutron.plugins.ml2.plugin.Ml2Plugin'
]

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

segment_type = sa.Enum('vlan', 'vxlan', name='segment_type')


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'cisco_ml2_n1kv_policy_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'cisco_ml2_n1kv_network_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('segment_type', segment_type, nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'cisco_ml2_n1kv_n1kv_port_bindings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('profile_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['profile_id'],
                                ['cisco_ml2_n1kv_policy_profiles.id']),
        sa.PrimaryKeyConstraint('port_id'),
    )

    op.create_table(
        'cisco_ml2_n1kv_network_bindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('segmentation_id', sa.Integer(), autoincrement=False,
                  nullable=False),
        sa.Column('profile_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['profile_id'],
                                ['cisco_ml2_n1kv_network_profiles.id']),
        sa.PrimaryKeyConstraint('network_id')
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('cisco_ml2_n1kv_port_bindings')
    op.drop_table('cisco_ml2_n1kv_network_bindings')
    op.drop_table('cisco_ml2_n1kv_network_profiles')
    op.drop_table('cisco_ml2_n1kv_policy_profiles')
