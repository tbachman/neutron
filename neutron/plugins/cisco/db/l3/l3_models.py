# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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
from sqlalchemy import orm

from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.plugins.cisco.db.device_manager import hd_models


class RouterType(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents Neutron router types.

    A router type is associated with a with hosting device template.
    The template is used when hosting device for the router type is created.

    Only 'id', 'name', 'description' are visible in non-admin context.
    """
    # name of router type, should preferably be unique
    name = sa.Column(sa.String(255), nullable=False)
    # description of this router type
    description = sa.Column(sa.String(255))
    # template to use to create hosting devices for this router type
    template_id = sa.Column(sa.String(36),
                            sa.ForeignKey('hostingdevicetemplates.id',
                                          ondelete='CASCADE'))
    template = orm.relationship(hd_models.HostingDeviceTemplate)
    # 'shared' is True if routertype is available to all tenants
    shared = sa.Column(sa.Boolean, default=True, nullable=False)
    # The number of slots this router type consume in hosting device
    slot_need = sa.Column(sa.Integer, autoincrement=False)
    # module to be used as scheduler for router of this type
    scheduler = sa.Column(sa.String(255), nullable=False)
    #TODO(bobmel): Add workflow driver to be used in agent for this routertype
    # module to be used by configuration agent for in-device configurations
    cfg_agent_driver = sa.Column(sa.String(255), nullable=False)


class RouterHostingDeviceBinding(model_base.BASEV2):
    """Represents binding between Neutron routers and their hosting devices."""
    __tablename__ = 'cisco_router_mappings'

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete='CASCADE'),
                          primary_key=True)
    router = orm.relationship(
        l3_db.Router,
        backref=orm.backref('hosting_info', cascade='all', uselist=False))
    # 'router_type_id' is id of router type for this router
    router_type_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('routertypes.id'),
        primary_key=True,
        nullable=False)
    router_type = orm.relationship(RouterType)
    # 'inflated_slot_need' is the slot need of the router plus the
    # number slots needed by other resources to be associated with the
    # router. It's only considered if > 0.
    inflated_slot_need = sa.Column(sa.Integer, default=0, autoincrement=False)
    # If 'auto_schedule' is True then router is automatically scheduled
    # if it lacks a hosting device or its hosting device fails.
    auto_schedule = sa.Column(sa.Boolean, default=True, nullable=False)
    share_hosting_device = sa.Column(sa.Boolean, default=True, nullable=False)
    # id of hosting device hosting this router, None/NULL if unscheduled.
    hosting_device_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('cisco_hosting_devices.id',
                                                ondelete='SET NULL'))
    hosting_device = orm.relationship(hd_models.HostingDevice)
