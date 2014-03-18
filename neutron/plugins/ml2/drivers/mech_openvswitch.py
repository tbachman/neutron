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
from oslo.config import cfg
import requests
import json
import glanceclient as glance_client
from novaclient.v3 import client as nova_client
from keystoneclient.v2_0 import client as keystone_client_v2
from neutron.openstack.common import excutils
from neutron.common import constants
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent

LOG = log.getLogger(__name__)

ml2_ovs = [
    cfg.StrOpt('listener_ep', default='http://192.168.101.14:6000'),
    cfg.StrOpt('keystone_ep', default='http://192.168.101.14:5000/v2.0'),
    cfg.StrOpt('keystone_user', default='admin'),
    cfg.StrOpt('keystone_pass', default='password')
]

cfg.CONF.register_opts(ml2_ovs, "ml2_ovs")

class OpenvswitchMechanismDriver(mech_agent.AgentMechanismDriverBase):
    """Attach to networks using openvswitch L2 agent.

    The OpenvswitchMechanismDriver integrates the ml2 plugin with the
    openvswitch L2 agent. Port binding with this driver requires the
    openvswitch agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """

    def __init__(self):
        super(OpenvswitchMechanismDriver, self).__init__(
            constants.AGENT_TYPE_OVS,
            portbindings.VIF_TYPE_OVS,
            True)

    def initialize(self):
        self.keystone_endpoint = cfg.CONF.ml2_ovs.keystone_ep
        self.keystone_user = cfg.CONF.ml2_ovs.keystone_user
        self.keystone_password = cfg.CONF.ml2_ovs.keystone_pass
        self.listener_ep = cfg.CONF.ml2_ovs.listener_ep

    def keystoneclient(self, context):
        tenant_id = context.current['tenant_id']
        return keystone_client_v2.Client(username=self.keystone_user,
                                         password=self.keystone_password,
                                         tenant_id=tenant_id,
                                         auth_url=self.keystone_endpoint)

    def create_port_postcommit(self, context):
        super(OpenvswitchMechanismDriver, self).create_port_postcommit(context)
        keystone = self.keystoneclient(context)
        services = keystone.services.list()
        token = keystone.auth_ref['token']['id']
        network_id = context.current['network_id']
        subnet_id = context.current['fixed_ips'][0]['subnet_id']
        dbcontext = context._plugin_context
        subnet = context._plugin.get_subnet(dbcontext, subnet_id)
        glance = None
        nova = None
        try:
            for service in services:
                if service.name == 'glance':
                    glance_id = service.id
                elif service.name == 'keystone':
                    nova_id = service.id

            endpoints = keystone.endpoints.list()
            for endpoint in endpoints:
                if endpoint.service_id == glance_id:
                    glance_ep = endpoint.adminurl
                    glance = glance_client.Client(1,
                                                  endpoint = glance_ep,
                                                  token = token)
                elif endpoint.service_id == nova_id:
                    nova_ep = endpoint.adminurl
                    nova = nova_client.Client(self.keystone_user,
                                              self.keystone_password,
                                              context.current['tenant_id'],
                                              auth_url=self.keystone_endpoint,
                                              tenant_id=context.current['tenant_id'])

            body = {}
            params = {
                        'vm': {},
                        'chain': {},
                        'gateway': {
                                'ip': '10.0.0.1',
                                'cidr': subnet['cidr']}
                     }
            body[context.current['device_id']] = {}
            if context.current['device_owner'] != 'network:dhcp':
                ports = context._plugin.get_ports(dbcontext)
                for port in ports:
                    if (port['network_id'] == network_id and
                        port['device_owner'].startswith('compute')):
                        body[port['device_id']] = {}
                        body[port['device_id']]['ip_address'] = port['fixed_ips'][0]['ip_address']
                        body[port['device_id']]['mac_address'] = port['mac_address']

                for instance in body.keys():
                    server = nova.servers.get(instance)
                    image = glance.images.get(server.image['id'])
                    for key, value in image.properties.items():
                        if key not in ['kernel_id','ramdisk_id']:
                            body[instance][key] = value

                    if instance == context.current['device_id']:
                        params['vm'][instance] = body[instance]
                    else:
                        params['chain'][instance] = body[instance]

                if self.listener_ep:
                    f = open('/tmp/out','w')
                    f.write(str(params))
                    f.close()
                    response = requests.post(self.listener_ep, data=json.dumps(params))
        except Exception:
            with excutils.save_and_reraise_exception():
                print "\n\n\n\n\n\n\n\n\n\n\n\n\nerror\n\n\n\n\n\n\n\n\n\n"

    def check_segment_for_agent(self, segment, agent):
        mappings = agent['configurations'].get('bridge_mappings', {})
        tunnel_types = agent['configurations'].get('tunnel_types', [])
        LOG.debug(_("Checking segment: %(segment)s "
                    "for mappings: %(mappings)s "
                    "with tunnel_types: %(tunnel_types)s"),
                  {'segment': segment, 'mappings': mappings,
                   'tunnel_types': tunnel_types})
        network_type = segment[api.NETWORK_TYPE]
        if network_type == 'local':
            return True
        elif network_type in tunnel_types:
            return True
        elif network_type in ['flat', 'vlan']:
            return segment[api.PHYSICAL_NETWORK] in mappings
        else:
            return False
