# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
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
# @author: Arvind Somya, Cisco Systems, Inc.
# @author: Kyle Mestery, Cisco Systems, Inc.

import base64
import httplib
import json
import uuid
import sys

from oslo.config import cfg

from neutron.agent import rpc as agent_rpc
from neutron.common import constants as q_const
from neutron.common import exceptions as exc
from neutron.common import topics
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.openstack.common import log
from neutron.openstack.common import rpc
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import rpc as plugin_rpc
from neutron.plugins.ml2.mechanism_drivers.opendaylight import config

LOG = log.getLogger(__name__)


DEFAULT_CONTAINER = 'default'
DEFAULT_PRIORITY = 1
SWITCH_LIST_PATH = '/controller/nb/v2/switch/%s/nodes/'
SWITCH_GET_PATH = '/controller/nb/v2/switch/%s/node/%s/%s'
HOST_LIST_PATH = '/controller/nb/v2/host/%s/'
FLOW_LIST_PATH = '/controller/nb/v2/flow/%s/'
FLOW_CREATE_PATH = '/controller/nb/v2/flow/%s/%s/%s/%s'
SUBNET_LIST_PATH = '/controller/nb/v2/subnet/%s'
SUBNET_CREATE_PATH = '/controller/nb/v2/subnet/%s/%s'
HOST_ADD_PATH = '/controller/nb/v2/host/%s/%s'
OVS_CONNECT_PATH = '/controller/nb/v2/networkconfig/bridgedomain/connect/%s/%s/%s'
BR_CREATE_PATH = '/controller/nb/v2/networkconfig/bridgedomain/bridge/OVS/%s/%s'

class OdlMechanismDriver(api.MechanismDriver):
    def initialize(self):
        # Make ODL connection and create integration bridge
        self.controllers = []
        controllers = cfg.CONF.odl.controllers.split(',')
        self.controllers.extend(controllers)
        
        # Get a list of all compute nodes
        # TODO: (asomya) Get a list of compute nodes from nova
        nodes = ['172.16.6.128']
        label_prefix = 'mgmt%d'
        label_num = 0
        self.connections = {}

        for node in nodes:
            label_num += 1
            label = label_prefix % label_num
            self.connections[label] = {}
            if self._connect_bridge_domain(label, node):
                self._create_bridge(label)
    
    def _rest_call(self, action, uri, headers, data=None):
        LOG.debug(_("Making rest call to controller at %s") % uri)

        data = data or {}
        (ip, port, username, password) = self.controllers[0].split(':')
        conn = httplib.HTTPConnection(ip, port)

        # Add auth
        auth = 'Basic %s' % \
               base64.encodestring('%s:%s' % (username, password)).strip()
        headers['Authorization'] = auth

        conn.request(action, uri, data, headers)
        response = conn.getresponse()
        respstr = response.read()

        return (response.status, respstr)

    def _connect_bridge_domain(self, label, domain, port='6634'):
        LOG.debug(_("Connecting to bridge domain"))
        uri = OVS_CONNECT_PATH % (label, domain, port)

        headers = {}
        (status, response) = self._rest_call('PUT', uri,
                                             headers, json.dumps({}))
        if status == 200:
            self.connections[label]['domain'] = domain
            return True

    def _create_bridge(self, label, brname=cfg.CONF.odl.integration_bridge):
        LOG.debug(_("Creating a bridge"))
        uri = BR_CREATE_PATH % (label, brname)

        headers = {}
        (status, response) = self._rest_call('POST', uri,
                                             headers, json.dumps({}))
        if status == 200:
            self.connections[label]['bridge'] = brname
            return True

    def _get_phy_br_port_id(self, context, switch_id,
                            container=DEFAULT_CONTAINER):
        LOG.debug(_("Getting physical bridge port openflow id"))
        if self.phy_br_port_id:
            return self.phy_br_port_id

        uri = SWITCH_GET_PATH % (container, 'OF', switch_id)
        headers = {}
        (status, response) = self._rest_call('GET', uri,
                                             headers, json.dumps({}))
        response = json.loads(response)
        if status == 200:
            for connector in response["nodeConnectorProperties"]:
                if str(connector['properties']['name']['nameValue']) == \
                    str(cfg.CONF.ODL.physical_bridge):
                    self.phy_br_port_id = connector['nodeconnector']['@id']
                    return self.phy_br_port_id

        return False

    def _add_port_drop_flow(self, context, switch_id, port_id,
                            of_port_id, priority, container):
        duuid = uuid.uuid4()
        xml = odl_xml_snippets.PORT_DROP_PACKET_XML % \
            (switch_id, of_port_id, duuid, priority)

        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, duuid)
        headers = {"Content-type": "application/xml"}
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, duuid, port_id, 'drop')
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _add_static_host(self, context, mac_address, switch_id, of_port_id,
                         node_ip, segmentation_id, container):
        query_args = '?dataLayerAddress=%s&nodeType=OF&nodeId=%s&'
        query_args += 'nodeConnectorType=OF&nodeConnectorId=%s&vlan=%s'
        query_args = query_args % (mac_address, switch_id, of_port_id,
                                   segmentation_id)
        uri = HOST_ADD_PATH % (container, node_ip)
        uri = uri + query_args
        (status, response) = self._rest_call('POST', uri, {}, json.dumps({}))
        if status == 201:
            LOG.debug(_("Host added"))
            #odl_db.add_port_flow(context.session, fuuid, port_id, 'setVlan')
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _port_outbound_setvlan_flow(self, context, switch_id, port_id,
                                    of_port_id, segmentation_id, priority,
                                    container):
        fuuid = uuid.uuid4()
        xml = odl_xml_snippets.PORT_VLAN_SET_FLOW_XML % (switch_id,
                                                         of_port_id, fuuid,
                                                         priority,
                                                         segmentation_id)

        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, fuuid)
        headers = {"Content-type": "application/xml"}
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, fuuid, port_id, 'setVlan')
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _port_inbound_strip_vlan_flow(self, context, switch_id, port_id,
                                      of_port_id, segmentation_id,
                                      priority, container):
        ruuid = uuid.uuid4()
        xml = odl_xml_snippets.INT_PORT_POP_VLAN_XML % (switch_id,
                                                        ruuid, priority,
                                                        segmentation_id,
                                                        of_port_id)

        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, ruuid)
        headers = {"Content-type": "application/xml"}
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, ruuid, port_id, 'popVlan')
        else:
            LOG.error(_("Error creating flow: %s") % response)
    
    def _add_port_gateway_flow(self, context, switch_id, port_id, of_port_id,
                               gateway_ip, priority, container):
        guuid = uuid.uuid4()
        xml = odl_xml_snippets.PORT_GATEWAY_FLOW_XML % (switch_id,
                                                        of_port_id,
                                                        guuid,
                                                        gateway_ip,
                                                        priority)

        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, guuid)
        headers = {"Content-type": "application/xml"}
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, guuid, port_id, 'gateway')
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _add_port_port_dual_flow(self, context, switch_id, ingress_id,
                                 egress_id, priority, container, label):

        duuid = uuid.uuid4()
        xml = odl_xml_snippets.PORT_DHCP_FLOW_XML % (switch_id,
                                                     ingress_id,
                                                     duuid,
                                                     priority,
                                                     egress_id)

        # Add forward flow
        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, duuid)
        headers = {"Content-type": "application/xml"}
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, duuid, ingress_id, label)
        else:
            LOG.error(_("Error creating flow: %s") % response)

        # Add reverse flow from dhcp port
        rduuid = uuid.uuid4()
        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, rduuid)
        xml = odl_xml_snippets.PORT_DHCP_FLOW_XML % (switch_id,
                                                     egress_id,
                                                     rduuid,
                                                     priority,
                                                     ingress_id)
        (status, response) = self._rest_call('POST', uri, headers, xml)
        if status == 201:
            odl_db.add_port_flow(context.session, rduuid, ingress_id, label)
        else:
            LOG.error(_("Error creating flow: %s") % response)

    def _create_port_add_flows(self, context, data,
                               container=DEFAULT_CONTAINER):
        LOG.debug(_("Creating port flows on controller"))
        port_id = data['port_id']
        # Get port info
        try:
            port = self.get_port(context, port_id)
        except Exception:
            return True

        # Get segmentation id
        segmentation_id = self.segmentation_manager.get_segmentation_id(
            context.session, port['network_id'])
        switch_id = '00:00:' + data['switch_id']
        port_name = data['vif_id'].split(',')[2].split('=')[1]
        of_port_id = data['vif_id'].split(',')[3].split('=')[1]

        # Store port data
        odl_db.add_ovs_port(context.session, port_id, of_port_id, port_name)

        # Get bridge port id
        #bport = self._get_phy_br_port_id(context, switch_id, container)

        # Add drop flow first
        """
        self._add_port_drop_flow(context, switch_id, port_id, of_port_id,
                                    DEFAULT_PRIORITY + 1, container)
        """

        # Add host and set vlan
        node_ip = port['fixed_ips'][0]['ip_address']
        self._add_static_host(context, port['mac_address'], switch_id,
                              of_port_id, node_ip, segmentation_id,
                              container)

        # Add setVlan flow now
        """
        self._port_outbound_setvlan_flow(context, switch_id, port_id,
                                            of_port_id, segmentation_id,
                                            DEFAULT_PRIORITY + 2, container)
        """

        # Add inbound flow
        """
        self._port_inbound_strip_vlan_flow(context, switch_id, port_id,
                                            of_port_id, segmentation_id,
                                            DEFAULT_PRIORITY + 2, container)
        """

        # Add port gateway flow
        # Get subnets for this network
        subnets = self.get_subnets(
            context, filters={'network_id': [port['network_id']]})
        for subnet in subnets:
            self._add_port_gateway_flow(context, switch_id, port_id,
                                        of_port_id, subnet['gateway_ip'],
                                        DEFAULT_PRIORITY + 2, container)

        # Add flow to dhcp port
        """
        if (port['device_owner'] != 'network:dhcp'):
            # Add a high priority path to the dhcp/bootp port
            # Get dhcp port for this network
            filters = {'device_owner': ['network:dhcp'],
                        'network_id': [port['network_id']]}
            ports = self.get_ports(
                        context,
                        filters=filters)
            for dport in ports:
                # Get of id for this port
                of_dport_id = odl_db.get_ovs_port(context.session,
                                                    dport['id']).of_port_id
                self._add_port_port_dual_flow(context, switch_id, of_port_id,
                                                of_dport_id,
                                                DEFAULT_PRIORITY + 3,
                                                container, 'dhcp')
        """

    def _delete_port_del_flow(self, context, data,
                              container=DEFAULT_CONTAINER):
        LOG.debug(_("Deleting port flows on controller"))
        port_id = data['port_id']
        switch_id = '00:00:' + data['switch_id']
        flows = odl_db.get_port_flows(context.session, port_id)

        for flow in flows:
            self._delete_flow(context, switch_id, flow['flow_id'])

    def _delete_flow(self, context, switch_id, flow_name,
                     container=DEFAULT_CONTAINER):
        LOG.debug(_("Deleting port flow on controller"))
        uri = FLOW_CREATE_PATH % (container, 'OF', switch_id, flow_name)
        headers = {"Accept": "application/json"}

        (status, response) = self._rest_call('DELETE', uri, headers,
                                             json.dumps({}))
        if status == 200:
            odl_db.del_port_flow(context.session, flow_name)
        else:
            LOG.error(_("Error deleting flow on controller: %s") % response)

    def _create_subnet(self, context, subnet, container=DEFAULT_CONTAINER):
        LOG.debug(_("Creating subnet gateway on controller"))
        name = False
        if subnet['name']:
            name = subnet['name']
        else:
            name = subnet['id']

        if subnet['gateway_ip']:
            uri = SUBNET_CREATE_PATH % (container, name)
            mask = subnet['cidr'].split('/')[1]
            headers = {"Accept": "application/json"}
            uri = uri + '?' + 'subnet=' + str(
                subnet['gateway_ip'] + '/' + mask)

            self._rest_call('POST', uri, headers, json.dumps({}))

    def _delete_subnet(self, context, id, container=DEFAULT_CONTAINER):
        LOG.debug(_("Deleting subnet gateway on controller"))
        uri = SUBNET_CREATE_PATH % (container, id)
        headers = {"Accept": "application/json"}
        self._rest_call('DELETE', uri, headers, json.dumps({}))

    def create_port_precommit(self, context):
        LOG.debug("\n\n\n\n\n%s\n\n\n" % context)

    def create_port_postcommit(self, context):
        pass
