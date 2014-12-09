# Copyright (c) 2014 Cisco Systems
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

import base64
import eventlet
import json
import requests

from oslo.config import cfg

from neutron.extensions import providernet
from neutron.openstack.common import excutils
from neutron.openstack.common.gettextutils import _LI
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers.cisco.n1kv import config  # noqa
from neutron.plugins.ml2.drivers.cisco.n1kv import constants as n1kv_const
from neutron.plugins.ml2.drivers.cisco.n1kv import exceptions as n1kv_exc

LOG = logging.getLogger(__name__)


class Client(object):

    """
    Client for the Cisco Nexus1000V Neutron Plugin.

    This client implements functions to communicate with
    Cisco Nexus1000V VSM.

    For every Neutron objects, Cisco Nexus1000V Neutron Plugin
    creates a corresponding object in the controller (Cisco
    Nexus1000V VSM).

    CONCEPTS:

    Following are few concepts used in Nexus1000V VSM:

    port-profiles:
    Policy profiles correspond to port profiles on Nexus1000V VSM.
    Port profiles are the primary mechanism by which network policy is
    defined and applied to switch interfaces in a Nexus 1000V system.

    network-segment:
    Each network-segment represents a broadcast domain.

    network-segment-pool:
    A network-segment-pool contains one or more network-segments.

    logical-network:
    A logical-network contains one or more network-segment-pools.

    bridge-domain:
    A bridge-domain is created when the network-segment is of type VXLAN.
    Each VXLAN <--> VLAN combination can be thought of as a bridge domain.

    ip-pool:
    Each ip-pool represents a subnet on the Nexus1000V VSM.


    WORK FLOW:

    For every network profile a corresponding logical-network and
    a network-segment-pool, under this logical-network, will be created.

    For every network created from a given network profile, a
    network-segment will be added to the network-segment-pool corresponding
    to that network profile.

    A port is created on a network and associated with a policy-profile.
    Hence for every unique combination of a network and a policy-profile, a
    unique vm-network will be created and a reference to the port will be
    added. If the same combination of network and policy-profile is used by
    another port, the references to that port will be added to the same
    vm-network.


    """

    # Define paths for the URI where the client connects for HTTP requests.
    port_profiles_path = "/virtual-port-profile"
    ports_path = "/kvm/vm-network/%s/ports"
    port_path = "/kvm/vm-network/%s/ports/%s"
    network_segment_path = "/network-segment/%s"
    network_segment_pool_path = "/network-segment-pool/%s"
    ip_pool_path = "/ip-pool-template/%s"
    vm_networks_path = "/kvm/vm-network"
    vm_network_path = "/kvm/vm-network/%s"
    bridge_domains_path = "/kvm/bridge-domain"
    bridge_domain_path = "/kvm/bridge-domain/%s"
    logical_network_path = "/logical-network/%s"

    pool = eventlet.GreenPool(cfg.CONF.ml2_cisco_n1kv.http_pool_size)

    def __init__(self, **kwargs):
        """Initialize a new client for the plugin."""
        self.format = 'json'
        self.n1kv_vsm_ip = cfg.CONF.ml2_cisco_n1kv.n1kv_vsm_ip
        self.username = cfg.CONF.ml2_cisco_n1kv.username
        self.password = cfg.CONF.ml2_cisco_n1kv.password
        self.action_prefix = 'http://%s/api/n1k' % self.n1kv_vsm_ip
        self.timeout = cfg.CONF.ml2_cisco_n1kv.http_timeout
        required_opts = ('n1kv_vsm_ip', 'username', 'password')
        for opt in required_opts:
            if not getattr(self, opt):
                raise cfg.RequiredOptError(opt, 'ml2_cisco_n1kv')

    def list_port_profiles(self):
        """Fetch all policy profiles from the VSM.

        :returns: JSON string
        """
        return self._get(self.port_profiles_path)

    def _create_logical_network(self, network_profile):
        """Create a logical network on the VSM.

        :param network_profile: network profile dict
        """
        body = {'description': network_profile['name']}
        logical_network_name = (network_profile['id'] +
                                n1kv_const.LOGICAL_NETWORK_SUFFIX)
        return self._post(self.logical_network_path % logical_network_name,
                          body=body)

    def _delete_logical_network(self, logical_network_name):
        """Delete a logical network on VSM.

        :param logical_network_name: string representing name of the logical
                                     network
        """
        return self._delete(
            self.logical_network_path % logical_network_name)

    def create_network_segment_pool(self, network_profile):
        """Create a network segment pool on the VSM.

        :param network_profile: network profile dict
        """
        self._create_logical_network(network_profile)
        logical_network_name = (network_profile['id'] +
                                n1kv_const.LOGICAL_NETWORK_SUFFIX)
        body = {'name': network_profile['name'],
                'description': network_profile['name'],
                'id': network_profile['id'],
                'logicalNetwork': logical_network_name}
        return self._post(
            self.network_segment_pool_path % network_profile['id'],
            body=body)

    def delete_network_segment_pool(self, network_segment_pool_id):
        """Delete a network segment pool on the VSM.

        :param network_segment_pool_id: UUID representing the network
                                        segment pool
        """
        logical_network_name = (network_segment_pool_id +
                                n1kv_const.LOGICAL_NETWORK_SUFFIX)
        self._delete(self.network_segment_pool_path %
                     network_segment_pool_id)
        return self._delete_logical_network(logical_network_name)

    def create_network_segment(self, network, network_profile):
        """Create a network segment on the VSM.

        :param network: network dict
        :param network_profile: network profile object
        """
        body = {'publishName': network['id'],
                'description': network['name'],
                'id': network['id'],
                'tenantId': network['tenant_id'],
                'mode': 'access',
                'segmentType': network_profile.segment_type,
                'networkSegmentPool': network_profile.id}
        if network[providernet.NETWORK_TYPE] == p_const.TYPE_VLAN:
            body['vlan'] = network[providernet.SEGMENTATION_ID]
        elif network[providernet.NETWORK_TYPE] == p_const.TYPE_VXLAN:
            # Create a bridge domain on VSM
            bd_name = network['id'] + n1kv_const.BRIDGE_DOMAIN_SUFFIX
            self._create_bridge_domain(network)
            body['bridgeDomain'] = bd_name
        try:
            return self._post(self.network_segment_path % network['id'],
                              body=body)
        except(n1kv_exc.VSMError, n1kv_exc.VSMConnectionFailed):
            with excutils.save_and_reraise_exception():
                # Clean up the bridge domain from the VSM for VXLAN networks.
                # Reraise the exception so that caller method executes further
                # clean up.
                if network[providernet.NETWORK_TYPE] == p_const.TYPE_VXLAN:
                    self._delete_bridge_domain(bd_name)

    def update_network_segment(self, updated_network):
        """Update a network segment on the VSM.

        :param updated_network: updated network dict
        """
        body = {'description': updated_network['name']}
        return self._post(self.network_segment_path % updated_network['id'],
                          body=body)

    def delete_network_segment(self, network_segment_id, network_type):
        """Delete a network segment on the VSM.

        :param network_segment_id: UUID representing the network segment
        :param network_type: type of network to be deleted
        """
        if network_type == p_const.TYPE_VXLAN:
            bd_name = network_segment_id + n1kv_const.BRIDGE_DOMAIN_SUFFIX
            self._delete_bridge_domain(bd_name)
        return self._delete(self.network_segment_path % network_segment_id)

    def _create_bridge_domain(self, network):
        """Create a bridge domain on VSM.

        :param network: network dict
        """
        groupIp = cfg.CONF.ml2_type_vxlan.vxlan_group
        if groupIp:
            vxlan_subtype = n1kv_const.MODE_NATIVE_VXLAN
        else:
            vxlan_subtype = n1kv_const.MODE_UNICAST
        body = {'name': network['id'] + n1kv_const.BRIDGE_DOMAIN_SUFFIX,
                'segmentId': network[providernet.SEGMENTATION_ID],
                'subType': vxlan_subtype,
                'tenantId': network['tenant_id']}
        if groupIp:
            body['groupIp'] = groupIp
        return self._post(self.bridge_domains_path,
                          body=body)

    def _delete_bridge_domain(self, name):
        """Delete a bridge domain on VSM.

        :param name: name of the bridge domain to be deleted
        """
        return self._delete(self.bridge_domain_path % name)

    def create_n1kv_port(self, port, vmnetwork_name, policy_profile):
        """Create a port on the VSM.

        :param port: port dict
        :param vmnetwork_name: name of the VM network
        :param policy_profile: policy profile object
        """
        body = {'name': vmnetwork_name,
                'networkSegmentId': port['network_id'],
                'networkSegment': port['network_id'],
                'portProfile': policy_profile.name,
                'portProfileId': policy_profile.id,
                'tenantId': port['tenant_id'],
                'portId': port['id'],
                'macAddress': port['mac_address'],
                }
        if port.get('fixed_ips'):
            body['ipAddress'] = port['fixed_ips'][0]['ip_address']
            body['subnetId'] = port['fixed_ips'][0]['subnet_id']
        return self._post(self.vm_networks_path,
                          body=body)

    def delete_n1kv_port(self, vmnetwork_name, port_id):
        """Delete a port on the VSM.

        :param vmnetwork_name: name of the VM network which imports this port
        :param port_id: UUID of the port
        """
        return self._delete(self.port_path % (vmnetwork_name, port_id))

    def _do_request(self, method, action, body=None,
                    headers=None):
        """Perform the HTTP request.

        The response is in either JSON format or plain text. A GET method will
        invoke a JSON response while a PUT/POST/DELETE returns message from the
        VSM in plain text format.
        Exception is raised when VSM replies with an INTERNAL SERVER ERROR HTTP
        status code (500) i.e. an error has occurred on the VSM or SERVICE
        UNAVAILABLE (404) i.e. VSM is not reachable.

        :param method: type of the HTTP request. POST, GET, PUT or DELETE
        :param action: path to which the client makes request
        :param body: dict for arguments which are sent as part of the request
        :param headers: header for the HTTP request
        :returns: JSON or plain text in HTTP response
        """
        action = self.action_prefix + action
        if not headers:
            headers = self._get_auth_header()
        headers['Content-Type'] = headers['Accept'] = "application/json"
        if body:
            body = json.dumps(body)
            LOG.debug("req: %s", body)
        try:
            resp = self.pool.spawn(requests.request,
                                   method,
                                   url=action,
                                   data=body,
                                   headers=headers,
                                   timeout=self.timeout).wait()
        except Exception as e:
            raise n1kv_exc.VSMConnectionFailed(reason=e)
        LOG.debug("status_code %s", resp.status_code)
        if resp.status_code == requests.codes.OK:
            if 'application/json' in resp.headers['content-type']:
                try:
                    return resp.json()
                except ValueError:
                    return {}
            elif 'text/plain' in resp.headers['content-type']:
                LOG.info(_LI("VSM: %s"), resp.text)
        else:
            raise n1kv_exc.VSMError(reason=resp.text)

    def _delete(self, action, body=None, headers=None):
        return self._do_request("DELETE", action, body=body,
                                headers=headers)

    def _get(self, action, body=None, headers=None):
        return self._do_request("GET", action, body=body,
                                headers=headers)

    def _post(self, action, body=None, headers=None):
        return self._do_request("POST", action, body=body,
                                headers=headers)

    def _put(self, action, body=None, headers=None):
        return self._do_request("PUT", action, body=body,
                                headers=headers)

    def _get_auth_header(self):
        """Retrieve header with auth info for the VSM.

        :return: authorization header dict
        """
        auth = base64.encodestring("%s:%s" % (self.username,
                                              self.password)).rstrip()
        return {"Authorization": "Basic %s" % auth}
