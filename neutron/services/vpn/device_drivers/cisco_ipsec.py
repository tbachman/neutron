# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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
import abc
from collections import namedtuple

import httplib

from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron import context
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import rpc
from neutron.openstack.common.rpc import proxy
from neutron.services.vpn.common import topics
from neutron.services.vpn import device_drivers
from neutron.services.vpn.device_drivers import (
    cisco_csr_rest_client as csr_client)


LOG = logging.getLogger(__name__)

RollbackStep = namedtuple('RollbackStep', ['action', 'resource_id', 'title'])


class CsrResourceCreateFailure(exceptions.NeutronException):
    message = _("Cisco CSR failed to create %(resource)s (%(which)s)")


class CsrDriverMismatchError(exceptions.NeutronException):
    message = _("Required %(resource)s attribute %(attr)s mapping for Cisco "
                "CSR is missing in device driver")


class CsrUnknownMappingError(exceptions.NeutronException):
    message = _("Device driver does not have a mapping of '%(value)s for "
                "attribute %(attr)s of %(resource)s")


class CiscoCsrIPsecVpnDriverApi(proxy.RpcProxy):
    """RPC API for agent to plugin messaging."""
    IPSEC_PLUGIN_VERSION = '1.0'

    def get_vpn_services_on_host(self, context, host):
        """Get list of vpnservices on this host.

        The vpnservices including related ipsec_site_connection,
        ikepolicy, ipsecpolicy, and Cisco info on this host.
        """
        return self.call(context,
                         self.make_msg('get_vpn_services_on_host',
                                       host=host),
                         version=self.IPSEC_PLUGIN_VERSION,
                         topic=self.topic)

    def update_status(self, context, status):
        """Update status for all VPN services and connections."""
        return self.cast(context,
                         self.make_msg('update_status',
                                       status=status),
                         version=self.IPSEC_PLUGIN_VERSION,
                         topic=self.topic)


class CiscoCsrIPsecDriver(device_drivers.DeviceDriver):
    """Cisco CSR VPN Device Driver for IPSec.

    This class is designed for use with L3-agent now.
    However this driver will be used with another agent in future.
    so the use of "Router" is kept minimul now.
    Insted of router_id,  we are using process_id in this code.
    """

    # history
    #   1.0 Initial version

    RPC_API_VERSION = '1.0'
    __metaclass__ = abc.ABCMeta

    def __init__(self, agent, host):
        self.agent = agent
        self.conf = self.agent.conf
        self.root_helper = self.agent.root_helper
        self.host = host
        self.conn = rpc.create_connection(new=True)
        self.context = context.get_admin_context_without_session()
        self.topic = topics.CISCO_IPSEC_AGENT_TOPIC
        node_topic = '%s.%s' % (self.topic, self.host)

        self.processes = {}
        self.process_status_cache = {}

        self.conn.create_consumer(
            node_topic,
            self.create_rpc_dispatcher(),
            fanout=False)
        self.conn.consume_in_thread()
        self.agent_rpc = (
            CiscoCsrIPsecVpnDriverApi(topics.CISCO_IPSEC_DRIVER_TOPIC, '1.0'))
        self.process_status_cache_check = loopingcall.FixedIntervalLoopingCall(
            self.report_status, self.context)
        self.process_status_cache_check.start(
            interval=self.conf.ipsec.ipsec_status_check_interval)

        # PCM: TEMP Stuff...Will only communicate with a hard coded CSR.
        # Later, will want to do a lazy connect on first use and get the
        # connection info for the desired router.
        # Obtain login info for CSR
        self.csr = csr_client.CsrRestClient('192.168.200.20',
                                            'stack', 'cisco',
                                            timeout=csr_client.TIMEOUT)
        self.connections = {}

    def create_rpc_dispatcher(self):
        return n_rpc.PluginRpcDispatcher([self])

    DIALECT_MAP = {'ike_policy': {'name': 'IKE Policy',
                                  'v1': u'v1',
                                  # auth_algorithm -> hash
                                  'sha1': u'sha',
                                  # encryption_algorithm -> encryption
                                  '3des': u'3des',
                                  'aes-128': u'aes',
                                  'aes-192': u'aes',  # TODO(pcm): fix
                                  'aes-256': u'aes',  # TODO(pcm): fix
                                  # pfs -> dhGroup
                                  'group2': 2,
                                  'group5': 5,
                                  'group14': 14},
                   'ipsec_policy': {'name': 'IPSec Policy',
                                    # auth_algorithm -> esp-authentication
                                    'sha1': u'esp-sha-hmac',
                                    # transform_protocol -> ah
                                    'esp': None,
                                    'ah': u'ah-sha-hmac',
                                    'ah-esp': u'ah-sha-hmac',
                                    # encryption_algorithm -> esp-encryption
                                    '3des': u'esp-3des',
                                    'aes-128': u'esp-aes',
                                    'aes-192': u'esp-aes',  # TODO(pcm) fix
                                    'aes-256': u'esp-aes',  # TODO(pcm) fix
                                    # pfs -> pfs
                                    'group2': u'group2',
                                    'group5': u'group5',
                                    'group14': u'group14'}}

    def translate_dialect(self, resource, attribute, info):
        """Map VPNaaS attributes values to CSR values for a resource."""
        name = self.DIALECT_MAP[resource]['name']
        if attribute not in info:
            raise CsrDriverMismatchError(resource=name, attr=attribute)
        value = info[attribute].lower()
        if value in self.DIALECT_MAP[resource]:
            return self.DIALECT_MAP[resource][value]
        raise CsrUnknownMappingError(resource=name, attr=attribute,
                                     value=value)

    def create_psk_info(self, psk_id, conn_info):
        """Collect/create attributes needed for pre-shared key."""
        return {u'keyring-name': psk_id,
                u'pre-shared-key-list': [
                    {u'key': conn_info['psk'],
                     u'encrypted': False,
                     u'peer-address': conn_info['peer_address']}]}

    def create_ike_policy_info(self, ike_policy_id, conn_info):
        """Collect/create/map attributes needed for IKE policy."""
        for_ike = 'ike_policy'
        policy_info = conn_info[for_ike]
        version = self.translate_dialect(for_ike,
                                         'ike_version',
                                         policy_info)
        encrypt_algorithm = self.translate_dialect(for_ike,
                                                   'encryption_algorithm',
                                                   policy_info)
        auth_algorithm = self.translate_dialect(for_ike,
                                                'auth_algorithm',
                                                policy_info)
        group = self.translate_dialect(for_ike,
                                       'pfs',
                                       policy_info)
        lifetime = policy_info['lifetime_value']
        return {u'version': version,
                u'priority-id': ike_policy_id,
                u'encryption': encrypt_algorithm,
                u'hash': auth_algorithm,
                u'dhGroup': group,
                u'version': version,
                u'lifetime': lifetime}

    def create_ipsec_policy_info(self, ipsec_policy_id, info):
        """Collect/create attributes needed for IPSec policy.

        Note: OpenStack will provide a default encryption algorithm, if one is
        not provided, so a authentication only configuration of (ah, sha1),
        which maps to ah-sha-hmac transform protocol, cannot be selected.
        As a result, we'll always configure the encryption algorithm, and
        will select ah-sha-hmac for transform protocol.
        """

        for_ipsec = 'ipsec_policy'
        policy_info = info[for_ipsec]
        transform_protocol = self.translate_dialect(for_ipsec,
                                                    'transform_protocol',
                                                    policy_info)
        auth_algorithm = self.translate_dialect(for_ipsec,
                                                'auth_algorithm',
                                                policy_info)
        encrypt_algorithm = self.translate_dialect(for_ipsec,
                                                   'encryption_algorithm',
                                                   policy_info)
        group = self.translate_dialect(for_ipsec, 'pfs', policy_info)
        lifetime = policy_info['lifetime_value']
        settings = {u'policy-id': ipsec_policy_id,
                    u'protection-suite': {
                        u'esp-encryption': encrypt_algorithm,
                        u'esp-authentication': auth_algorithm},
                    u'lifetime-sec': lifetime,
                    u'pfs': group,
                    # TODO(pcm): Remove when CSR fixes 'Disable'
                    u'anti-replay-window-size': u'64'}
        if transform_protocol:
            settings[u'protection-suite'][u'ah'] = transform_protocol
        return settings

    def create_site_connection_info(self, site_conn_id, ipsec_policy_id,
                                    conn_info):
        """Collect/create attributes needed for the IPSec connection."""
        # gw_ip = vpnservice['external_ip'] (need to pass in)
        mtu = conn_info['mtu']
        return {
            u'vpn-interface-name': site_conn_id,
            u'ipsec-policy-id': ipsec_policy_id,
            u'local-device': {
                # TODO(pcm): Get CSR port of interface with local subnet
                u'ip-address': u'GigabitEthernet3',
                # TODO(pcm): Get IP address of router's public I/F, once CSR is
                # used as embedded router.
                u'tunnel-ip-address': u'172.24.4.23'
                # u'tunnel-ip-address': u'%s' % gw_ip
            },
            u'remote-device': {
                u'tunnel-ip-address': conn_info['peer_address']
            },
            u'mtu': mtu
        }

    def create_routes_info(self, site_conn_id, conn_info):
        """Collect/create attributes for static routes."""
        routes_info = []
        for peer_cidr in conn_info.get('peer_cidrs', []):
            route = {u'destination-network': peer_cidr,
                     u'outgoing-interface': site_conn_id}
            route_id = self.csr.make_route_id(peer_cidr, site_conn_id)
            routes_info.append((route_id, route))
        return routes_info

    def _check_create(self, resource, which):
        """Determine if REST create request was successful."""
        if self.csr.status == httplib.CREATED:
            LOG.debug("PCM: %(resource)s %(which)s is configured",
                      {'resource': resource, 'which': which})
            return
        LOG.error(_("PCM: Unable to create %(resource)s %(which)s: "
                    "%(status)d"),
                  {'resource': resource, 'which': which,
                   'status': self.csr.status})
        # ToDO(pcm): Set state to error
        raise CsrResourceCreateFailure(resource=resource, which=which)

    def do_create_action(self, action_suffix, info, resource_id, title):
        """Perform a single REST step for IPSec site connection create."""
        create_action = 'create_%s' % action_suffix
        try:
            getattr(self.csr, create_action)(info)
        except AttributeError:
            LOG.exception(_("Internal error - '%s' is not defined"),
                          create_action)
            raise CsrResourceCreateFailure(resource=title,
                                           which=resource_id)
        self._check_create(title, resource_id)
        self.steps.append(RollbackStep(action_suffix, resource_id, title))

    def _verify_deleted(self, status, resource, which):
        """Determine if REST delete request was successful."""
        if status in (httplib.NO_CONTENT, httplib.NOT_FOUND):
            LOG.debug("PCM: %(resource)s configuration %(which)s is removed",
                      {'resource': resource, 'which': which})
        else:
            LOG.warning(_("PCM: Unable to delete %(resource)s %(which)s: "
                          "%(status)d"), {'resource': resource,
                                          'which': which,
                                          'status': status})

    def do_rollback(self):
        """Undo create steps that were completed successfully."""
        for step in reversed(self.steps):
            delete_action = 'delete_%s' % step.action
            LOG.debug(_("PCM: Performing rollback action %(action)s for "
                        "resource %(resource)s"), {'action': delete_action,
                                                   'resource': step.title})
            try:
                getattr(self.csr, delete_action)(step.resource_id)
            except AttributeError:
                LOG.exception(_("Internal error - '%s' is not defined"),
                              delete_action)
                raise CsrResourceCreateFailure(resource=step.title,
                                               which=step.resource_id)
            self._verify_deleted(self.csr.status, step.title, step.resource_id)
        self.steps = []

    def create_ipsec_site_connection(self, context, conn_info):
        """Creates an IPSec site-to-site connection on CSR.

        Create the PSK, IKE policy, IPSec policy, connection, static route,
        and (future) DPD.
        """
        # Get all the IDs
        conn_id = conn_info['id']
        psk_id = conn_id
        site_conn_id = conn_info['cisco']['site_conn_id']
        ike_policy_id = conn_info['cisco']['ike_policy_id']
        ipsec_policy_id = conn_info['cisco']['ipsec_policy_id']

        LOG.info(_('PCM: Device driver:create_ipsec_site_connection %s'),
                 conn_id)
        # Get all the attributes needed to create
        try:
            psk_info = self.create_psk_info(psk_id, conn_info)
            ike_policy_info = self.create_ike_policy_info(ike_policy_id,
                                                          conn_info)
            ipsec_policy_info = self.create_ipsec_policy_info(ipsec_policy_id,
                                                              conn_info)
            connection_info = self.create_site_connection_info(site_conn_id,
                                                               ipsec_policy_id,
                                                               conn_info)
            routes_info = self.create_routes_info(site_conn_id, conn_info)
        except (CsrUnknownMappingError, CsrDriverMismatchError) as e:
            LOG.exception(e)
            return

        try:
            self.steps = []
            self.do_create_action('pre_shared_key', psk_info,
                                  conn_id, 'Pre-Shared Key')
            self.do_create_action('ike_policy', ike_policy_info,
                                  ike_policy_id, 'IKE Policy')
            self.do_create_action('ipsec_policy', ipsec_policy_info,
                                  ipsec_policy_id, 'IPSec Policy')
            self.do_create_action('ipsec_connection', connection_info,
                                  site_conn_id, 'IPSec Connection')

            # TODO(pcm): Do DPD and handle if >1 connection and different DPD
            for route_id, route_info in routes_info:
                self.do_create_action('static_route', route_info,
                                      route_id, 'Static Route')
        except CsrResourceCreateFailure:
            self.do_rollback()
            LOG.info(_("FAILED: Create of IPSec site-to-site connection %s"),
                     conn_id)
        else:
            self.connections[conn_id] = self.steps
            LOG.info(_("SUCCESS: Created IPSec site-to-site connection %s"),
                     conn_id)
            # TODO(pcm) Set connection status to PENDING_CREATE?

    def delete_ipsec_site_connection(self, context, conn_info):
        """Delete site-to-site IPSec connection.

        This will be best effort and will continue, if there are any
        failures.
        """
        conn_id = conn_info['site_conn']['id']
        LOG.info(_('PCM: Device driver:delete_ipsec_site_connection %s'),
                 conn_id)
        self.steps = self.connections.get(conn_id, [])
        if not self.steps:
            LOG.warning(_('PCM: Unable to find connection %s'), conn_id)
        else:
            self.do_rollback()

        LOG.info(_("COMPLETED: Deleted IPSec site-to-site connection %s"),
                 conn_id)

    def create_router(self, process_id):
        """Handling create router event.

        Agent calls this method, when the process namespace
        is ready.
        """
        LOG.debug("PCM: Ignoring create_router call")
        return
#         if process_id in self.processes:
#             # In case of vpnservice is created
#             # before router's namespace
#             process = self.processes[process_id]
#             # self._update_nat(process.vpnservice, self.agent.add_nat_rule)
#             process.enable()

    def destroy_router(self, process_id):
        """Handling destroy_router event.

        Agent calls this method, when the process namespace
        is deleted.
        """
        LOG.debug("PCM: Ignoring destroy_router call")
        return
#         if process_id in self.processes:
#             process = self.processes[process_id]
#             process.disable()
#            vpnservice = process.vpnservice
#             if vpnservice:
#                 self._update_nat(vpnservice, self.agent.remove_nat_rule)
#             del self.processes[process_id]

    def report_status(self, context):
        """Report status of all VPN services and conn to plugin."""
        vpnservices = self.agent_rpc.get_vpn_services_on_host(
            context, self.host)
        LOG.debug("PCM: status %s", vpnservices)
        self.update_status_and_report(vpnservices, context)

    def update_status_and_report(self, vpnservices, context):
        """Update and report status for VPN services and their connections."""
        LOG.debug("PCM: Ignoring status update")
        return
#         status_changed_vpn_services = []
#         for process in self.processes.values():
#             previous_status = self.get_process_status_cache(process)
#             if self.is_status_updated(process, previous_status):
#                 new_status = self.copy_process_status(process)
#                 self.process_status_cache[process.id] = new_status
#                 status_changed_vpn_services.append(new_status)
#                 # We need unset updated_pending status after it
#                 # is reported to the server side
#                 self.unset_updated_pending_status(process)
#
#         if status_changed_vpn_services:
#             self.agent_rpc.update_status(
#                 context,
#                 status_changed_vpn_services)

    def vpnservice_updated(self, context, **kwargs):
        """Handle VPNaaS service driver change notifications."""
        self.sync(context, [])

    @lockutils.synchronized('vpn-agent', 'neutron-')
    def sync(self, context, routers):
        """Sync status with server side.

        :param context: context object for RPC call
        :param routers: Router objects which is created in this sync event

        There could be many failure cases should be
        considered including the followings.
        1) Agent class restarted
        2) Failure on process creation
        3) VpnService is deleted during agent down
        4) RPC failure

        In order to handle, these failure cases,
        This driver takes simple sync strategies.

        TODO(pcm): Determine if/how to handle the above failures.
        """
        vpnservices = self.agent_rpc.get_vpn_services_on_host(
            context, self.host)
        LOG.debug("PCM: sync start for %d VPN services", len(vpnservices))
        for vpnservice in vpnservices:
            LOG.debug(_("PCM: Processing service %s"), vpnservice)
            for ipsec_conn in vpnservice['ipsec_conns']:
                LOG.debug(_("PCM: Processing connection %s"), ipsec_conn)
                self.create_ipsec_site_connection(context, ipsec_conn)
        # TODO(pcm) OK, or should we get the latest status from service driver?
        self.update_status_and_report(vpnservices, context)
