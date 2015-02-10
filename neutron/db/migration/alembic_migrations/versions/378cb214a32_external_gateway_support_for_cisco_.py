# Copyright 2015 OpenStack Foundation
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

"""External gateway support for Cisco Nexus L3 service plugin

Revision ID: 378cb214a32
Revises: 22c2b94a0f22
Create Date: 2015-02-17 12:09:02.918696

"""

# revision identifiers, used by Alembic.
revision = '378cb214a32'
down_revision = '22c2b94a0f22'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


def upgrade():
    op.add_column('cisco_nexus_vrf_binding',
    sa.Column('gateway_ip', sa.String(length=255), nullable=False)
    )


def downgrade():
    op.drop_column('cisco_nexus_vrf_binding',
    'gateway_ip'
    )
