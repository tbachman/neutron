# Copyright (c) 2013 OpenStack Foundation
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
# @author: Kyle Mestery, Cisco Systems, Inc.

from oslo.config import cfg
import requests

from neutron.extensions import portbindings
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.openvswitch.common import constants

LOG = log.getLogger(__name__)

odl_opts = [
    cfg.StrOpt('url',
               help=_("HTTP URL of OpenDaylight REST interface.")),
    cfg.StrOpt('username',
               help=_("HTTP username for authentication")),
    cfg.StrOpt('password', secret=True,
               help=_("HTTP password for authentication")),
    cfg.IntOpt('timeout', default=10,
               help=_("HTTP timeout in seconds."))
]

cfg.CONF.register_opts(odl_opts, "ml2_odl")


class OpenDaylightMechanismDriver(api.MechanismDriver):

    """Mechanism Driver for OpenDaylight.

    This driver was a port from the Tail-F NCS MechanismDriver.  The API
    exposed by ODL is slightly different from the API exposed by NCS,
    but the general concepts are the same.
    """
    def initialize(self):
        self.url = cfg.CONF.ml2_odl.url
        self.timeout = cfg.CONF.ml2_odl.timeout
        self.username = cfg.CONF.ml2_odl.username
        self.password = cfg.CONF.ml2_odl.password
        self.vif_type = portbindings.VIF_TYPE_OVS
        self.cap_port_filter = False

    # Postcommit hooks are used to trigger synchronization.

    def create_network_postcommit(self, context):
        self.sync_object('create', 'networks', context)

    def update_network_postcommit(self, context):
        self.sync_object('update', 'networks', context)

    def delete_network_postcommit(self, context):
        self.sync_object('delete', 'networks', context)

    def create_subnet_postcommit(self, context):
        self.sync_object('create', 'subnets', context)

    def update_subnet_postcommit(self, context):
        self.sync_object('update', 'subnets', context)

    def delete_subnet_postcommit(self, context):
        self.sync_object('delete', 'subnets', context)

    def create_port_postcommit(self, context):
        self.sync_object('create', 'ports', context)

    def update_port_postcommit(self, context):
        self.sync_object('update', 'ports', context)

    def delete_port_postcommit(self, context):
        self.sync_object('delete', 'ports', context)

    def sync_object(self, operation, object_type, context):
        """Synchronize the single modified record to ODL.
        """
        dbcontext = context._plugin_context
        id = context.current['id']
        if operation == 'delete':
            urlpath = object_type + '/' + id
            self.sendjson('delete', urlpath, None)
        else:
            assert operation == 'create' or operation == 'update'
            if operation == 'create':
                urlpath = object_type
                method = 'post'
            else:
                urlpath = object_type + '/' + id
                method = 'put'
            if object_type == 'networks':
                network = context._plugin.get_network(dbcontext, id)
                # Remove the following for update calls
                if operation == 'update':
                    del network['id']
                    del network['status']
                    del network['subnets']
                    del network['tenant_id']
                self.sendjson(method, urlpath, {'network': network})
            elif object_type == 'subnets':
                subnet = context._plugin.get_subnet(dbcontext, id)
                # Remove the following for update calls
                if operation == 'update':
                    del subnet['id']
                    del subnet['network_id']
                    del subnet['ip_version']
                    del subnet['cidr']
                    del subnet['allocation_pools']
                    del subnet['tenant_id']
                self.sendjson(method, urlpath, {'subnet': subnet})
            else:
                assert object_type == 'ports'
                port = context._plugin.get_port(dbcontext, id)
                self.add_security_groups(context, dbcontext, port)
                if operation == 'create':
                    # TODO(kmestery): Converting to uppercase due to ODL bug
                    port['mac_address'] = port['mac_address'].upper()
                elif operation == 'update':
                    # Remove the following for update calls
                    del port['network_id']
                    del port['id']
                    del port['status']
                    del port['mac_address']
                    del port['tenant_id']
                    del port['fixed_ips']
                self.sendjson(method, urlpath, {'port': port})

    def add_security_groups(self, context, dbcontext, port):
        """Populate the 'security_groups' field with entire records."""
        groups = [context._plugin.get_security_group(dbcontext, sg)
                  for sg in port['security_groups']]
        port['security_groups'] = groups

    def sendjson(self, method, urlpath, obj):
        headers = {'Content-Type': 'application/json'}
        if obj is None:
            data = None
        else:
            data = jsonutils.dumps(obj, indent=2)
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)
        if self.url:
            url = '/'.join([self.url, urlpath])
            LOG.debug(_('ODL-----> sending URL (%s) <-----ODL') % url)
            LOG.debug(_('ODL-----> sending JSON (%s) <-----ODL') % obj)
            r = requests.request(method, url=url,
                                 headers=headers, data=data,
                                 auth=auth, timeout=self.timeout)
            r.raise_for_status()

    def bind_port(self, context):
        LOG.debug(_("Attempting to bind port %(port)s on "
                    "network %(network)s"),
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        for segment in context.network.network_segments:
            if self.check_segment(segment):
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.cap_port_filter)
                LOG.debug(_("Bound using segment: %s"), segment)
                return
            else:
                LOG.error(_("Failed binding port for segment ID %(id)s, "
                            "segment %(seg)s, phys net %(physnet)s, and "
                            "network type %(nettype)s"),
                          {'id': segment[api.ID],
                           'seg': segment[api.SEGMENTATION_ID],
                           'physnet': segment[api.PHYSICAL_NETWORK],
                           'nettype': segment[api.NETWORK_TYPE]})

    def validate_port_binding(self, context):
        if self.check_segment(context.bound_segment):
            LOG.debug(_('Binding valid.'))
            return True
        LOG.warning(_("Binding invalid for port: %s"), context.current)
        return False

    def unbind_port(self, context):
        LOG.debug(_("Unbinding port %(port)s on "
                    "network %(network)s"),
                  {'port': context.current['id'],
                   'network': context.network.current['id']})

    def check_segment(self, segment):
        """Verify a segment is valid for the OpenDaylight MechanismDriver

        Verify the requested segment is supported by ODL and return True or
        False to indicate this to callers.
        """
        network_type = segment[api.NETWORK_TYPE]
        if network_type == 'local':
            return True
        elif network_type in [constants.TYPE_GRE, constants.TYPE_VXLAN]:
            return True
        elif network_type in ['flat', 'vlan']:
            #TODO(mestery): Validate these
            return True
        else:
            return False
