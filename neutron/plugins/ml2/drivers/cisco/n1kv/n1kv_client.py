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
#
# @author: Abhishek Raut (abhraut@cisco.com), Cisco Systems Inc.

import base64
import eventlet
import requests

from oslo.config import cfg

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
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

    vm-network:
    vm-network refers to a network-segment and policy-profile.
    It maintains a list of ports that uses the network-segment and
    policy-profile this vm-network refers to.


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
    network_segment_path = "/network-segment/%s"
    network_segment_pool_path = "/network-segment-pool/%s"
    ip_pool_path = "/ip-pool-template/%s"
    ports_path = "/kvm/vm-network/%s/ports"
    port_path = "/kvm/vm-network/%s/ports/%s"
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
        """
        Fetch all policy profiles from the VSM.

        :returns: JSON string
        """
        return self._get(self.port_profiles_path)

    def create_logical_network(self, network_profile, tenant_id):
        """
        Create a logical network on the VSM.

        :param network_profile: network profile dict
        :param tenant_id: UUID representing the tenant
        """
        LOG.debug(_("Logical network"))
        body = {'description': network_profile['name'],
                'tenantId': tenant_id}
        logical_network_name = (network_profile['id'] +
                                n1kv_const.LOGICAL_NETWORK_SUFFIX)
        return self._post(self.logical_network_path % logical_network_name,
                          body=body)

    def delete_logical_network(self, logical_network_name):
        """
        Delete a logical network on VSM.

        :param logical_network_name: string representing name of the logical
                                     network
        """
        return self._delete(
            self.logical_network_path % logical_network_name)

    def create_network_segment_pool(self, network_profile, tenant_id):
        """
        Create a network segment pool on the VSM.

        :param network_profile: network profile dict
        :param tenant_id: UUID representing the tenant
        """
        LOG.debug(_("network_segment_pool"))
        logical_network_name = (network_profile['id'] +
                                n1kv_const.LOGICAL_NETWORK_SUFFIX)
        body = {'name': network_profile['name'],
                'description': network_profile['name'],
                'id': network_profile['id'],
                'logicalNetwork': logical_network_name,
                'tenantId': tenant_id}
        return self._post(
            self.network_segment_pool_path % network_profile['id'],
            body=body)

    def update_network_segment_pool(self, network_profile):
        """
        Update a network segment pool on the VSM.

        :param network_profile: network profile dict
        """
        body = {'name': network_profile['name'],
                'description': network_profile['name']}
        return self._post(self.network_segment_pool_path %
                          network_profile['id'], body=body)

    def delete_network_segment_pool(self, network_segment_pool_id):
        """
        Delete a network segment pool on the VSM.

        :param network_segment_pool_id: UUID representing the network
                                        segment pool
        """
        return self._delete(self.network_segment_pool_path %
                            network_segment_pool_id)

    def _do_request(self, method, action, body=None,
                    headers=None):
        """
        Perform the HTTP request.

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
            body = jsonutils.dumps(body, indent=2)
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
        LOG.debug(_("status_code %s"), resp.status_code)
        if resp.status_code == requests.codes.OK:
            if 'application/json' in resp.headers['content-type']:
                try:
                    return resp.json()
                except ValueError:
                    return {}
            elif 'text/plain' in resp.headers['content-type']:
                LOG.debug(_("VSM: %s"), resp.text)
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
        """
        Retrieve header with auth info for the VSM.

        :return: authorization header dict
        """
        auth = base64.encodestring("%s:%s" % (self.username,
                                              self.password)).rstrip()
        header = {"Authorization": "Basic %s" % auth}
        return header
