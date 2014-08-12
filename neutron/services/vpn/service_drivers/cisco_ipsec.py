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

from neutron.common import rpc as n_rpc
from neutron.db.vpn import vpn_db
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.vpn.common import topics
from neutron.services.vpn import service_drivers
from neutron.services.vpn.service_drivers import (
    cisco_cfg_loader as workaround)
from neutron.services.vpn.service_drivers import cisco_csr_db as csr_id_map
from neutron.services.vpn.service_drivers import cisco_validator

LOG = logging.getLogger(__name__)

IPSEC = 'ipsec'
BASE_IPSEC_VERSION = '1.0'
LIFETIME_LIMITS = {'IKE Policy': {'min': 60, 'max': 86400},
                   'IPSec Policy': {'min': 120, 'max': 2592000}}
MIN_CSR_MTU = 1500
MAX_CSR_MTU = 9192

# TODO(pcm): When available obtain this from the Cisco plugin constants
# from neutron.plugins.cisco.device_manager.plugging_drivers import (
#    n1kv_plugging_constants as n1kv_constants)
T2_PORT_NAME = "t2_p:"


class CiscoCsrIPsecVpnDriverCallBack(n_rpc.RpcCallback):

    """Handler for agent to plugin RPC messaging."""

    # history
    #   1.0 Initial version

    RPC_API_VERSION = BASE_IPSEC_VERSION

    def __init__(self, driver):
        super(CiscoCsrIPsecVpnDriverCallBack, self).__init__()
        self.driver = driver

    @property
    def l3_plugin(self):
        try:
            return self._l3_plugin
        except AttributeError:
            self._l3_plugin = manager.NeutronManager.get_service_plugins().get(
                constants.L3_ROUTER_NAT)
            return self._l3_plugin

    def create_rpc_dispatcher(self):
        return n_rpc.PluginRpcDispatcher([self])

    def get_vpn_services_using(self, context, router_id):
        LOG.debug("PCM: Collecting VPN services on router %s", router_id)
        query = context.session.query(vpn_db.VPNService)
        query = query.join(vpn_db.IPsecSiteConnection)
        query = query.join(vpn_db.IKEPolicy)
        query = query.join(vpn_db.IPsecPolicy)
        query = query.join(vpn_db.IPsecPeerCidr)
        query = query.filter(vpn_db.VPNService.router_id == router_id)
        return query.all()

    def get_vpn_services_on_host(self, context, host=None):
        """Returns info on the VPN services on the host."""
        # TODO(pcm): Use this, once Cisco L3 router plugin support up-streamed
        # routers = self.l3_plugin.get_active_routers_for_host(context, host)
        routers = workaround.get_active_routers_for_host(context, host)
        host_vpn_services = []
        for router in routers:
            LOG.debug("PCM: router=%s %s", router['id'], router)
            vpn_services = self.get_vpn_services_using(context, router['id'])
            LOG.debug("PCM: services on host %s", vpn_services)
            for vpn_service in vpn_services:
                host_vpn_services.append(
                    self.driver._make_vpnservice_dict(context, vpn_service,
                                                      router))
        LOG.debug("PCM: have vpn_services %s", host_vpn_services)
        return host_vpn_services

    def update_status(self, context, status):
        """Update status of all vpnservices."""
        plugin = self.driver.service_plugin
        plugin.update_status_by_agent(context, status)


class CiscoCsrIPsecVpnAgentApi(service_drivers.BaseIPsecVpnAgentApi,
                               n_rpc.RpcCallback):

    """API and handler for Cisco IPSec plugin to agent RPC messaging."""

    RPC_API_VERSION = BASE_IPSEC_VERSION

    def __init__(self, topic, default_version):
        super(CiscoCsrIPsecVpnAgentApi, self).__init__(
            topics.CISCO_IPSEC_AGENT_TOPIC, topic, default_version)

    def _agent_notification(self, context, method, router_id,
                            version=None, **kwargs):
        """Notify update for the agent.

        Find the host for the router being notified and then
        dispatches a notification for the VPN device driver.
        """
        admin_context = context.is_admin and context or context.elevated()
        if not version:
            version = self.RPC_API_VERSION
        # TODO(pcm): Use this, when Cisco L3 router plugin support up-streamed
        # host = self.l3_plugin.get_host_for_router(admin_context, router_id)
        host = workaround.get_host_for_router(admin_context, router_id)
        LOG.debug(_('Notify agent at %(topic)s.%(host)s the message '
                    '%(method)s %(args)s for router %(router)s'),
                  {'topic': self.to_agent_topic,
                   'host': host,
                   'method': method,
                   'args': kwargs,
                   'router': router_id})
        self.cast(context, self.make_msg(method, **kwargs),
                  version=version,
                  topic='%s.%s' % (self.to_agent_topic, host))


class CiscoCsrIPsecVPNDriver(service_drivers.VpnDriver):

    """Cisco CSR VPN Service Driver class for IPsec."""

    def __init__(self, service_plugin):
        super(CiscoCsrIPsecVPNDriver, self).__init__(
            service_plugin,
            cisco_validator.CiscoCsrVpnValidator(service_plugin))
        self.endpoints = [CiscoCsrIPsecVpnDriverCallBack(self)]
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.CISCO_IPSEC_DRIVER_TOPIC, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = CiscoCsrIPsecVpnAgentApi(
            topics.CISCO_IPSEC_AGENT_TOPIC, BASE_IPSEC_VERSION)
        self._l3_plugin = None
        LOG.debug("PCM: Initialized service driver")

    @property
    def l3_plugin(self):
        if self._l3_plugin is None:
            self._l3_plugin = manager.NeutronManager.get_service_plugins().get(
                constants.L3_ROUTER_NAT)
            LOG.debug("PCM: Have L3 plugin %s", self._l3_plugin)
        return self._l3_plugin

    @property
    def service_type(self):
        return IPSEC

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        csr_id_map.create_tunnel_mapping(context, ipsec_site_connection)
        LOG.debug("PCM: sending create notification")
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'],
                                          reason='ipsec-conn-create')

    def update_ipsec_site_connection(
        self, context, old_ipsec_site_connection, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(
            context, vpnservice['router_id'],
            reason='ipsec-conn-update')

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'],
                                          reason='ipsec-conn-delete')

    def create_ikepolicy(self, context, ikepolicy):
        pass

    def delete_ikepolicy(self, context, ikepolicy):
        pass

    def update_ikepolicy(self, context, old_ikepolicy, ikepolicy):
        pass

    def create_ipsecpolicy(self, context, ipsecpolicy):
        pass

    def delete_ipsecpolicy(self, context, ipsecpolicy):
        pass

    def update_ipsecpolicy(self, context, old_ipsec_policy, ipsecpolicy):
        pass

    def create_vpnservice(self, context, vpnservice):
        pass

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'],
                                          reason='vpn-service-update')

    def delete_vpnservice(self, context, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'],
                                          reason='vpn-service-delete')

    def get_cisco_connection_mappings(self, conn_id, context):
        """Obtain persisted mappings for IDs related to connection."""
        tunnel_id, ike_id, ipsec_id = csr_id_map.get_tunnel_mapping_for(
            conn_id, context.session)
        return {'site_conn_id': u'Tunnel%d' % tunnel_id,
                'ike_policy_id': u'%d' % ike_id,
                'ipsec_policy_id': u'%s' % ipsec_id}

    def _create_tunnel_interface(self, router_info):
        return router_info['mgmt_intf']
# TODO(pcm): Enable this code, once Cisco L3 router plugin up-streamed
#         # Use the first inteface
#         port = router_info['_interfaces'][0]['hosting_info']
#         vlan = port['segmentation_id']
#         # Port name "currently" is t{1,2}_p:1, as only one router per CSR,
#         # but will keep a semi-generic algorithm
#         port_name = port['hosting_port_name']
#         name, sep, num = port_name.partition(':')
#         # TODO(pcm): When available use n1kv_constants.T2_PORT_NAME
#         offset = 1 if name in T2_PORT_NAME else 0
#         if_num = int(num) * 2 + offset
#         return 'GigabitEthernet%d.%d' % (if_num, vlan)

    def _get_router_info(self, router_info, external_ip):
        LOG.debug("PCM: Getting router info %s", router_info)
        hosting_device = router_info['hosting_device']
        return {'rest_mgmt_ip': hosting_device['management_ip_address'],
                'external_ip': external_ip,
                'username': hosting_device['credentials']['username'],
                'password': hosting_device['credentials']['password'],
                'tunnel_if_name': self._create_tunnel_interface(router_info),
                'protocol_port': 443,  # TODO(pcm) Available from router?
                'timeout': 30}  # Hard-coded for now

    def _make_vpnservice_dict(self, context, vpnservice, router_info):
        """Collect all info on service, including Cisco info per IPSec conn."""
        vpnservice_dict = dict(vpnservice)
        vpnservice_dict['ipsec_conns'] = []
        vpnservice_dict['subnet'] = dict(vpnservice.subnet)
        vpnservice_dict['router_info'] = self._get_router_info(router_info,
            vpnservice.router.gw_port['fixed_ips'][0]['ip_address'])
        for ipsec_conn in vpnservice.ipsec_site_connections:
            ipsec_conn_dict = dict(ipsec_conn)
            ipsec_conn_dict['ike_policy'] = dict(ipsec_conn.ikepolicy)
            ipsec_conn_dict['ipsec_policy'] = dict(ipsec_conn.ipsecpolicy)
            ipsec_conn_dict['peer_cidrs'] = [
                peer_cidr.cidr for peer_cidr in ipsec_conn.peer_cidrs]
            ipsec_conn_dict['cisco'] = self.get_cisco_connection_mappings(
                ipsec_conn['id'], context)
            vpnservice_dict['ipsec_conns'].append(ipsec_conn_dict)
        return vpnservice_dict
