# Copyright 2013, Paul Michali, Cisco Systems, Inc.
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
#import netaddr

from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.openstack.common.rpc import proxy
from neutron.plugins.common import constants
from neutron.services.vpn.common import topics
from neutron.services.vpn import service_drivers
from neutron.services.vpn.service_drivers import cisco_csr_db as csr_id_map


LOG = logging.getLogger(__name__)

IPSEC = 'ipsec'
BASE_IPSEC_VERSION = '1.0'
LIFETIME_LIMITS = {'IKE Policy': {'min': 60, 'max': 86400},
                   'IPSec Policy': {'min': 120, 'max': 2592000}}
MIN_CSR_MTU = 1500
MAX_CSR_MTU = 9192


class CsrValidationFailure(exceptions.NeutronException):
    message = _("Cisco CSR does not support %(resource)s attribute %(key)s "
                "with value '%(value)s'")


class CiscoCsrIPsecVpnDriverCallBack(object):

    """Handler for agent to plugin RPC messaging."""

    # history
    #   1.0 Initial version

    RPC_API_VERSION = BASE_IPSEC_VERSION

    def __init__(self, driver):
        self.driver = driver

    def create_rpc_dispatcher(self):
        return n_rpc.PluginRpcDispatcher([self])

    def get_vpn_services_on_host(self, context, host=None):
        """Retuns info on the vpnservices on the host."""
        LOG.debug(_("PCM: get_vpn_services_on_host"))
        plugin = self.driver.service_plugin
        vpnservices = plugin._get_agent_hosting_vpn_services(
            context, host)
        return [self.driver._make_vpnservice_dict(vpnservice, context)
                for vpnservice in vpnservices]

    def update_status(self, context, status):
        """Update status of vpnservices."""
        plugin = self.driver.service_plugin
        plugin.update_status_by_agent(context, status)


class CiscoCsrIPsecVpnAgentApi(proxy.RpcProxy):

    """API and handler for plugin to agent RPC messaging."""

    RPC_API_VERSION = BASE_IPSEC_VERSION

    def _agent_notification(self, context, method, router_id,
                            version=None, **kwargs):
        """Notify update for the agent.

        This method will find where is the router, and
        dispatch notification for the agent.
        """
        adminContext = context.is_admin and context or context.elevated()
        plugin = manager.NeutronManager.get_service_plugins().get(
            constants.L3_ROUTER_NAT)
        if not version:
            version = self.RPC_API_VERSION
        l3_agents = plugin.get_l3_agents_hosting_routers(
            adminContext, [router_id],
            admin_state_up=True,
            active=True)
        for l3_agent in l3_agents:
            LOG.debug(_('Notify agent at %(topic)s.%(host)s the message '
                        '%(method)s'),
                      {'topic': topics.CISCO_IPSEC_AGENT_TOPIC,
                       'host': l3_agent.host,
                       'method': method,
                       'args': kwargs})
            self.cast(
                context, self.make_msg(method, **kwargs),
                version=version,
                topic='%s.%s' % (topics.CISCO_IPSEC_AGENT_TOPIC,
                                 l3_agent.host))

    def vpnservice_updated(self, context, router_id):
        """Send update event of vpnservices."""
        method = 'vpnservice_updated'
        self._agent_notification(context, method, router_id)

    # TODO(pcm) Remove, once converted over
    def create_ipsec_site_connection(self, context, router_id, conn_info):
        """Send device driver create IPSec site-to-site connection request."""
        LOG.debug('PCM: IPSec connection create with %(router)s %(conn)s',
                  {'router': router_id, 'conn': conn_info})
        self._agent_notification(context, 'create_ipsec_site_connection',
                                 router_id, conn_info=conn_info)

    def delete_ipsec_site_connection(self, context, router_id, conn_info):
        """Send device driver delete IPSec site-to-site connection request."""
        LOG.debug('PCM: IPSec connection delete with %(router)s %(conn)s',
                  {'router': router_id, 'conn': conn_info})
        self._agent_notification(context, 'delete_ipsec_site_connection',
                                 router_id, conn_info=conn_info)


class CiscoCsrIPsecVPNDriver(service_drivers.VpnDriver):

    """Cisco CSR VPN Service Driver class for IPsec."""

    def __init__(self, service_plugin):
        self.callbacks = CiscoCsrIPsecVpnDriverCallBack(self)
        self.service_plugin = service_plugin
        self.conn = rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.CISCO_IPSEC_DRIVER_TOPIC,
            self.callbacks.create_rpc_dispatcher(),
            fanout=False)
        self.conn.consume_in_thread()
        self.agent_rpc = CiscoCsrIPsecVpnAgentApi(
            topics.CISCO_IPSEC_AGENT_TOPIC, BASE_IPSEC_VERSION)

    @property
    def service_type(self):
        return IPSEC

    def get_lifetime(self, for_policy, policy_info):
        units = policy_info['lifetime']['units']
        if units != 'seconds':
            raise CsrValidationFailure(resource=for_policy,
                                       key='lifetime:units',
                                       value=units)
        value = policy_info['lifetime']['value']
        if (value < LIFETIME_LIMITS[for_policy]['min'] or
            value > LIFETIME_LIMITS[for_policy]['max']):
            raise CsrValidationFailure(resource=for_policy,
                                       key='lifetime:value',
                                       value=value)
        return value

    def get_ike_version(self, policy_info):
        version = policy_info['ike_version']
        if version != 'v1':
            raise CsrValidationFailure(resource='IKE Policy',
                                       key='ike_version',
                                       value=version)
        return version

    def get_mtu(self, conn_info):
        mtu = conn_info['mtu']
        if mtu < MIN_CSR_MTU or mtu > MAX_CSR_MTU:
            raise CsrValidationFailure(resource='IPSec Connection',
                                       key='mtu',
                                       value=mtu)
        return mtu

    def get_router_public_ip(self, vpn_service):
        gw_port = vpn_service.router.gw_port
        if gw_port and len(gw_port.fixed_ips) == 1:
            return gw_port.fixed_ips[0].ip_address
        else:
            raise CsrValidationFailure(resource='IPSec Connection',
                                       key='router:gw_port:ip_address',
                                       value='missing')

    def get_cisco_connection_info(self, context, site_conn, vpn_service):
        public_ip = self.get_router_public_ip(vpn_service)
        ipsec_policy_id = site_conn['ipsecpolicy_id']
        csr_ipsec_policy_id = ipsec_policy_id.replace('-', '')[:31]
        tunnel_id, ike_id = csr_id_map.get_tunnel_mapping_for(site_conn['id'],
                                                              context.session)
        return {'site_conn_id': u'Tunnel%d' % tunnel_id,
                'ike_policy_id': u'%d' % ike_id,
                'ipsec_policy_id': u'%s' % csr_ipsec_policy_id,
                'router_public_ip': public_ip}

    def _build_ipsec_site_conn_create_info(self, context, site_conn,
                                           vpn_service):
        ike_info = self.service_plugin.get_ikepolicy(context,
                                                     site_conn['ikepolicy_id'])
        ipsec_info = self.service_plugin.get_ipsecpolicy(
            context, site_conn['ipsecpolicy_id'])
        csr_id_map.create_tunnel_mapping(context, site_conn)
        cisco_info = self.get_cisco_connection_info(context, site_conn,
                                                    vpn_service)
        return {'site_conn': site_conn,
                'ike_policy': ike_info,
                'ipsec_policy': ipsec_info,
                'cisco': cisco_info}

    def _build_ipsec_site_conn_delete_info(self, context, site_conn,
                                           vpn_service):
        cisco_info = self.get_cisco_connection_info(context, site_conn,
                                                    vpn_service)
        return {'site_conn': site_conn, 'cisco': cisco_info}

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        LOG.debug(_("PCM: New Cisco driver create_ipsec_site_connection"))
        # TODO(pcm) Do validation, before notifying device driver
        csr_id_map.create_tunnel_mapping(context, ipsec_site_connection)
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    # TODO(pcm) Remove these three functions, once switch...
#     def create_ipsec_site_connection(self, context, ipsec_site_connection):
#         vpn_service = self.service_plugin._get_vpnservice(
#             context, ipsec_site_connection['vpnservice_id'])
#         conn_info = self._build_ipsec_site_conn_create_info(
#             context, ipsec_site_connection, vpn_service)
#         self.agent_rpc.create_ipsec_site_connection(
#             context, vpn_service['router_id'], conn_info=conn_info)

    def update_ipsec_site_connection(
        self, context, old_ipsec_site_connection, ipsec_site_connection):
        # TODO(pcm): Implement...
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        vpn_service = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        conn_info = self._build_ipsec_site_conn_delete_info(
            context, ipsec_site_connection, vpn_service)
        self.agent_rpc.delete_ipsec_site_connection(
            context, vpn_service['router_id'], conn_info=conn_info)
        csr_id_map.delete_tunnel_mapping(context, ipsec_site_connection)

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
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def delete_vpnservice(self, context, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def get_cisco_connection_mappings(self, site_conn, context):
        """Perform transform and obtain persisted mappings for IDs."""
        ipsec_policy_id = site_conn['ipsecpolicy_id']
        csr_ipsec_policy_id = ipsec_policy_id.replace('-', '')[:31]
        tunnel_id, ike_id = csr_id_map.get_tunnel_mapping_for(site_conn['id'],
                                                              context.session)
        return {'site_conn_id': u'Tunnel%d' % tunnel_id,
                'ike_policy_id': u'%d' % ike_id,
                'ipsec_policy_id': u'%s' % csr_ipsec_policy_id}

    def _make_vpnservice_dict(self, vpnservice, context):
        """Collect all info on service, including Cisco info per IPSec conn."""
        # TODO(pcm) Future: trim to only needed fields?
        vpnservice_dict = dict(vpnservice)
        vpnservice_dict['ipsec_conns'] = []
        vpnservice_dict['subnet'] = dict(
            vpnservice.subnet)
        vpnservice_dict['external_ip'] = vpnservice.router.gw_port[
            'fixed_ips'][0]['ip_address']
        for ipsec_conn in vpnservice.ipsec_site_connections:
            ipsec_conn_dict = dict(ipsec_conn)
# PART OF VALIDATION Move to create section
#             try:
#                 netaddr.IPAddress(ipsec_conn['peer_id'])
#             except netaddr.core.AddrFormatError:
#                 ipsec_conn['peer_id'] = (
#                     '@' + ipsec_conn['peer_id'])
            ipsec_conn_dict['ike_policy'] = dict(ipsec_conn.ikepolicy)
            ipsec_conn_dict['ipsec_policy'] = dict(ipsec_conn.ipsecpolicy)
            ipsec_conn_dict['peer_cidrs'] = [
                peer_cidr.cidr for peer_cidr in ipsec_conn.peer_cidrs]
            ipsec_conn_dict['cisco'] = self.get_cisco_connection_mappings(
                ipsec_conn, context)
            vpnservice_dict['ipsec_conns'].append(ipsec_conn_dict)
        return vpnservice_dict
