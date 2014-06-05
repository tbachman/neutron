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
#
# @author: Hareesh Puthalath, Cisco Systems, Inc.

import eventlet
import netaddr

from neutron.common import constants as l3_constants
from neutron.common import topics
from neutron.common import utils as common_utils
from neutron import context as n_context
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.openstack.common.rpc import common as rpc_common
from neutron.openstack.common.rpc import proxy

from neutron.plugins.cisco.cfg_agent.cfg_exceptions import DriverException
from neutron.plugins.cisco.cfg_agent.device_drivers.driver_mgr import (
    DeviceDriverManager)
from neutron.plugins.cisco.cfg_agent.device_status import DeviceStatus
from neutron.plugins.cisco.cfg_agent.service_helpers.service_helper import (
    ServiceHelperBase)
from neutron.plugins.cisco.common import cisco_constants as c_constants

LOG = logging.getLogger(__name__)

N_ROUTER_PREFIX = 'nrouter-'


class RouterInfo(object):
    """Wrapper class around the (neutron) router dictionary.

    Information about the neutron router is exchanged as a python dictionary
    between plugin and config agent. RouterInfo is a wrapper around that dict,
    with attributes for common parameters. These attributes keep the state
    of the current router configuration, and are used for detecting router
    state changes when an updated router dict is received.

    This is a modified version of the RouterInfo class defined in the
    (reference) l3-agent implementation, for use with cisco config agent.
    """

    def __init__(self, router_id, router):
        self.router_id = router_id
        self.ex_gw_port = None
        self._snat_enabled = None
        self._snat_action = None
        self.internal_ports = []
        self.floating_ips = []
        self.router = router
        self.routes = []
        self.ha_info = None
        # Set 'ha_info' if present
        if router.get('ha_info') is not None:
            self.ha_info = router['ha_info']

    @property
    def router(self):
        return self._router

    @property
    def snat_enabled(self):
        return self._snat_enabled

    @router.setter
    def router(self, value):
        self._router = value
        if not self._router:
            return
        # enable_snat by default if it wasn't specified by plugin
        self._snat_enabled = self._router.get('enable_snat', True)

    def router_name(self):
        return N_ROUTER_PREFIX + self.router_id


class CiscoRoutingPluginApi(proxy.RpcProxy):
    """RoutingServiceHelper(Agent) side of the  routing RPC API."""

    BASE_RPC_API_VERSION = '1.1'

    def __init__(self, topic, host):
        super(CiscoRoutingPluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def get_routers(self, context, router_ids=None, hd_ids=[]):
        """Make a remote process call to retrieve the sync data for routers.

        :param context: session context
        :param router_ids: list of  routers to fetch
        :param hd_ids : hosting device ids, only routers assigned to these
                        hosting devices will be returned.
        """
        return self.call(context,
                         self.make_msg('cfg_sync_routers', host=self.host,
                                       router_ids=router_ids,
                                       hosting_device_ids=hd_ids),
                         topic=self.topic)

    def get_external_network_id(self, context):
        """Make a remote process call to retrieve the external network id.

        :param context : session context
        :raise common.RemoteError: with TooManyExternalNetworks
                                   as exc_type if there are
                                   more than one external network
        """
        return self.call(context,
                         self.make_msg('get_external_network_id',
                                       host=self.host),
                         topic=self.topic)


class RoutingServiceHelper(ServiceHelperBase):

    def __init__(self, host, conf, cfg_agent):
        self.conf = conf
        self.cfg_agent = cfg_agent
        self.context = n_context.get_admin_context_without_session()
        self.plugin_rpc = CiscoRoutingPluginApi(topics.L3PLUGIN, host)
        self._dev_status = DeviceStatus()
        self._drivermgr = DeviceDriverManager()

        self.router_info = {}
        self.updated_routers = set()
        self.removed_routers = set()

        self.fullsync = True
        self.topic = '%s.%s' % (c_constants.CFG_AGENT_L3_ROUTING, host)
        self._setup_rpc()
        # self.agent = cfg_agent
        # Short cut for attributes in agent
        # self._dev_status = self.agent._dev_status
        # self.plugin_rpc = self.agent.plugin_rpc
        # self.conf = self.agent.conf
        # self.context = self.agent.context
        # self.router_info = self.agent.router_info

    def _setup_rpc(self):
        self.conn = rpc.create_connection(new=True)
        self.dispatcher = self.create_rpc_dispatcher()
        self.conn.create_consumer(
            self.topic,
            self.dispatcher,
            fanout=False)
        self.conn.consume_in_thread()

    ### Notifications from Plugin ####
    def router_deleted(self, context, router_id):
        """Deal with router deletion RPC message."""
        LOG.debug(_('Got router deleted notification for %s'), router_id)
        self.removed_routers.add(router_id)

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        LOG.debug(_('Got routers updated notification :%s'), routers)
        if routers:
            # This is needed for backward compatibility
            if isinstance(routers[0], dict):
                routers = [router['id'] for router in routers]
            self.updated_routers.update(routers)

    def router_removed_from_agent(self, context, payload):
        LOG.debug(_('Got router removed from agent :%r'), payload)
        self.removed_routers.add(payload['router_id'])

    def router_added_to_agent(self, context, payload):
        LOG.debug(_('Got router added to agent :%r'), payload)
        self.routers_updated(context, payload)

    def _router_added(self, router_id, router):
        """Operations when a router is added.

        Create a new RouterInfo object for this router and add it to the
        service helpers router_info dictionary.  Then `router_added()` is
        called on the device driver.

        :param router_id: id of the router
        :param router: router dict
        :return: None
        """
        ri = RouterInfo(router_id, router)
        driver = self._drivermgr.get_driver(ri)
        driver.router_added(ri)
        self.router_info[router_id] = ri

    def _router_removed(self, router_id, deconfigure=True):
        """Operations when a router is removed.

        Get the RouterInfo object corresponding to the router in the service
        helpers's router_info dict. If deconfigure is set to True,
        remove this router's configuration from the hosting device.
        :param router_id: id of the router
        :param deconfigure: if True, the router's configuration is deleted from
        the hosting device.
        :return:
        """
        ri = self.router_info.get(router_id)
        if ri is None:
            LOG.warn(_("Info for router %s was not found. "
                       "Skipping router removal"), router_id)
            return
        ri.router['gw_port'] = None
        ri.router[l3_constants.INTERFACE_KEY] = []
        ri.router[l3_constants.FLOATINGIP_KEY] = []
        try:
            if deconfigure:
                #ToDo: Check here
                self.process_router(ri)
                driver = self._drivermgr.get_driver(ri)
                driver.router_removed(ri, deconfigure)
                self._drivermgr.remove_driver(router_id)
            del self.router_info[router_id]
            self.removed_routers.discard(router_id)
        except DriverException:
            LOG.info(_("Router remove for router_id: %s was incomplete. "
                       "Adding the router to removed_routers list"), router_id)
            self.removed_routers.add(router_id)
            # remove this router from updated_routers if it is there. It might
            # end up there too if exception was thrown inside `process_router`
            self.updated_routers.discard(router_id)

    def internal_network_added(self, ri, port, ex_gw_port):
        driver = self._drivermgr.get_driver(ri)
        driver.internal_network_added(ri, port)
        if ri.snat_enabled and ex_gw_port:
            driver.enable_internal_network_NAT(ri, port, ex_gw_port)

    def internal_network_removed(self, ri, port, ex_gw_port):
        driver = self._drivermgr.get_driver(ri)
        driver.internal_network_removed(ri, port)
        if ri.snat_enabled and ex_gw_port:
            driver.disable_internal_network_NAT(ri, port, ex_gw_port)

    def external_gateway_added(self, ri, ex_gw_port):
        driver = self._drivermgr.get_driver(ri)
        driver.external_gateway_added(ri, ex_gw_port)
        if ri.snat_enabled and ri.internal_ports:
            for port in ri.internal_ports:
                driver.enable_internal_network_NAT(ri, port, ex_gw_port)

    def external_gateway_removed(self, ri, ex_gw_port):
        driver = self._drivermgr.get_driver(ri)
        if ri.snat_enabled and ri.internal_ports:
            for port in ri.internal_ports:
                driver.disable_internal_network_NAT(ri, port, ex_gw_port)
        driver.external_gateway_removed(ri, ex_gw_port)

    def floating_ip_added(self, ri, ex_gw_port, floating_ip, fixed_ip):
        driver = self._drivermgr.get_driver(ri)
        driver.floating_ip_added(ri, ex_gw_port, floating_ip, fixed_ip)

    def floating_ip_removed(self, ri, ex_gw_port, floating_ip, fixed_ip):
        driver = self._drivermgr.get_driver(ri)
        driver.floating_ip_removed(ri, ex_gw_port, floating_ip, fixed_ip)

    # def process_service_old(self, *args, **kwargs):
    #     """Process changes to the routers managed by this connfig agent.
    #
    #     Entry point to the routing service helper. Config agent calls this
    #     function periodically as part of the rpc_loop.
    #     The latest state of any updated routers are fetched. If full sync,
    #     data on all the routers are fetched.
    #     The routers are then sorted on the hosting device where they are
    #     configured. Then process_routers() is called on thread per device.
    #
    #     :param args:
    #     :param kwargs:
    #     :return: None
    #     """
    #     try:
    #         LOG.debug(_("Starting processing routing service"))
    #         resources = {}
    #         if self.fullsync:
    #             LOG.debug(_("FullSync flag is on. Starting fullsync"))
    #             self.fullsync = False
    #             self.updated_routers.clear()
    #             self.removed_routers.clear()
    #             routers = self.plugin_rpc.get_routers(self.context)
    #             resources['routers'] = routers
    #         else:
    #             LOG.debug(_("Processing %(ur)d updated routers and %(rr)d "
    #                         "removed routers"),
    #                       {'ur': len(self.updated_routers),
    #                        'rr': len(self.removed_routers)})
    #             if self.updated_routers:
    #                 router_ids = list(self.updated_routers)
    #                 self.updated_routers.clear()
    #                 routers = self.plugin_rpc.get_routers(
    #                     self.context, router_ids)
    #                 resources['routers'] = routers
    #             if self.removed_routers:
    #                 removed_routers = {}
    #                 for r_id in self.removed_routers:
    #                     removed_routers[r_id] = self.router_info[r_id]
    #                 resources['removed_routers'] = removed_routers
    #         # Sort on hosting device
    #         hosting_devices = self._sort_resources_per_hosting_device(
    #             resources)
    #         # Dispatch process_services() for each hosting device
    #         pool = eventlet.GreenPool()
    #         for device_id, resources in hosting_devices.items():
    #             routers = resources.get('routers')
    #             removed_routers = resources.get('removed_routers')
    #             pool.spawn_n(self.process_routers, routers, removed_routers,
    #                          device_id, all_routers=self.fullsync)
    #         pool.waitall()
    #         LOG.debug(_("Routing service processing successfully completed"))
    #     except rpc_common.RPCException:
    #         LOG.exception(_("Failed processing routers due to RPC error"))
    #         self.fullsync = True
    #     except Exception:
    #         LOG.exception(_("Failed processing routers"))
    #         self.fullsync = True

    def process_service(self, device_ids=None, removed_router_ids=None):
        try:
            LOG.debug(_("Routing service processing started"))
            resources = {}
            routers = {}
            removed_routers = {}
            if self.fullsync:
                LOG.debug(_("FullSync flag is on. Starting fullsync"))
                self.fullsync = False
                self.updated_routers.clear()
                self.removed_routers.clear()
                routers = self._fetch_router_info(all_routers=True)
            else:
                if device_ids:
                    LOG.debug(_("Processing routers on:%s"), device_ids)
                    routers = self._fetch_router_info(device_ids)
                if self.updated_routers:
                    router_ids = list(self.updated_routers)
                    LOG.debug(_("Updated routers:%s"), list(router_ids))
                    self.updated_routers.clear()
                    routers.append(self._fetch_router_info(
                        router_ids=router_ids))
                if removed_router_ids:
                    self.removed_routers.union(set(removed_router_ids))
                if self.removed_routers:
                    LOG.debug(_("Removed routers:%s"),
                              list(self.removed_routers))
                    for r_id in self.removed_routers:
                        removed_routers[r_id] = self.router_info[r_id]
            # Add everything to resource dict
            resources['routers'] = routers
            if removed_routers:
                resources['removed_routers'] = removed_routers
            # Sort on hosting device
            hosting_devices = self._sort_resources_per_hosting_device(
                resources)
            # Dispatch process_services() for each hosting device
            pool = eventlet.GreenPool()
            for device_id, resources in hosting_devices.items():
                routers = resources.get('routers')
                removed_routers = resources.get('removed_routers')
                pool.spawn_n(self.process_routers, routers, removed_routers,
                             device_id, all_routers=self.fullsync)
            pool.waitall()
            LOG.debug(_("Routing service processing successfully completed"))
        except Exception:
            LOG.exception(_("Failed processing routers"))
            self.fullsync = True

    def _fetch_router_info(self, router_ids=[], device_ids=[],
                           all_routers=False):
        try:
            if all_routers:
                return self.plugin_rpc.get_routers(self.context)
            if router_ids:
                return self.plugin_rpc.get_routers(self.context, router_ids)
            if device_ids:
                return self.plugin_rpc.get_routers(self.context,
                                                   hd_ids=device_ids)
        except rpc_common.RPCException:
            LOG.exception(_("RPC Error in fetching routers from plugin"))
            self.fullsync = True

    def process_routers(self, routers, removed_routers,
                        device_id=None, all_routers=False):
        """Process the set of routers.

        Iterating on the set of routers received and comparing it with the
        set of routers already in the routing service helper,
        new routers which are added are identified. Then check the
        reachability (via ping) of hosting device where the router is hosted
        and backlogs it if necessary.
        For routers which are only updated, call `process_router()` on them.

        When all_routers is set to True (because of a full sync),
        this will result in the detection and deletion of routers which are
        to be removed.

        :param routers: The set of routers to be processed
        :param removed_routers: the set of routers which where removed
        :param device_id: Id of the hosting device
        :param all_routers: Flag for specifying a partial list of routers
        :return: None
        """
        try:
            if all_routers:
                prev_router_ids = set(self.router_info)
            else:
                prev_router_ids = set(self.router_info) & set(
                    [router['id'] for router in routers])
            cur_router_ids = set()
            for r in routers:
                if not r['admin_state_up']:
                    continue
                # Note: Whether the router can only be assigned to a particular
                # hosting device is decided and enforced by the plugin.
                # So no checks are done here.
                cur_router_ids.add(r['id'])
                if not self._dev_status.is_hosting_device_reachable(r['id'], r):
                    LOG.info(
                        _("Router: %(id)s is on unreachable hosting device. "
                          "Skip processing it."), {'id': r['id']})
                    continue
                if r['id'] not in self.router_info:
                    self._router_added(r['id'], r)
                ri = self.router_info[r['id']]
                ri.router = r
                self.process_router(ri)
            # identify and remove routers that no longer exist
            for router_id in prev_router_ids - cur_router_ids:
                self._router_removed(router_id)
            if removed_routers:
                for router in removed_routers:
                    self._router_removed(router['id'])
                    # self.removed_routers.remove(router['id'])
        except:
            LOG.exception(_("Exception in processing routers on device:%s"),
                          device_id)
            self.fullsync = True

    def process_router(self, ri):
        """Process a router, apply latest configuration and update router_info.

        Get the router dict from  RouterInfo and proceed to detect changes
        from the last known state. When new ports or deleted ports are
        detected, `internal_network_added()` or `internal_networks_removed()`
        are called accordingly. Similarly changes in ex_gw_port causes
         `external_gateway_added()` or `external_gateway_removed()` calls.
        Next, floating_ips and routes are processed. Also, latest state is
        stored in ri.internal_ports and ri.ex_gw_port for future comparisons.

        :param ri : neutron.plugins.cisco.l3.agent.router_info.RouterInfo
        corresponding to the router being processed.
        :return:None
        :raises: neutron.plugins.cisco.l3.common.exceptions.DriverException if
        the configuration operation fails.
        """
        try:
            ex_gw_port = ri.router.get('gw_port')
            ri.ha_info = ri.router.get('ha_info', None)
            internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
            existing_port_ids = set([p['id'] for p in ri.internal_ports])
            current_port_ids = set([p['id'] for p in internal_ports
                                    if p['admin_state_up']])
            new_ports = [p for p in internal_ports
                         if
                         p['id'] in (current_port_ids - existing_port_ids)]
            old_ports = [p for p in ri.internal_ports
                         if p['id'] not in current_port_ids]

            for p in new_ports:
                self._set_subnet_info(p)
                self.internal_network_added(ri, p, ex_gw_port)
                ri.internal_ports.append(p)

            for p in old_ports:
                self.internal_network_removed(ri, p, ri.ex_gw_port)
                ri.internal_ports.remove(p)

            if ex_gw_port and not ri.ex_gw_port:
                self._set_subnet_info(ex_gw_port)
                self.external_gateway_added(ri, ex_gw_port)
            elif not ex_gw_port and ri.ex_gw_port:
                self.external_gateway_removed(ri, ri.ex_gw_port)

            if ex_gw_port:
                self.process_router_floating_ips(ri, ex_gw_port)

            ri.ex_gw_port = ex_gw_port
            self.routes_updated(ri)
        except DriverException as e:
            with excutils.save_and_reraise_exception():
                LOG.error(e)

    def process_router_floating_ips(self, ri, ex_gw_port):
        """Process a router's floating ips.

        Compare current floatingips (in ri.floating_ips) with the router's
        updated floating ips (in ri.router.floating_ips) and detect
        flaoting_ips which were added or removed. Notify driver of
        the change via `floating_ip_added()` or `floating_ip_removed()`.

        :param ri:  neutron.plugins.cisco.l3.agent.router_info.RouterInfo
        corresponding to the router being processed.
        :param ex_gw_port: Port dict of the external gateway port.
        :return: None
        :raises: neutron.plugins.cisco.l3.common.exceptions.DriverException if
        the configuration operation fails.
        """

        floating_ips = ri.router.get(l3_constants.FLOATINGIP_KEY, [])
        existing_floating_ip_ids = set(
            [fip['id'] for fip in ri.floating_ips])
        cur_floating_ip_ids = set([fip['id'] for fip in floating_ips])

        id_to_fip_map = {}

        for fip in floating_ips:
            if fip['port_id']:
                # store to see if floatingip was remapped
                id_to_fip_map[fip['id']] = fip
                if fip['id'] not in existing_floating_ip_ids:
                    ri.floating_ips.append(fip)
                    self.floating_ip_added(ri, ex_gw_port,
                                           fip['floating_ip_address'],
                                           fip['fixed_ip_address'])

        floating_ip_ids_to_remove = (existing_floating_ip_ids -
                                     cur_floating_ip_ids)
        for fip in ri.floating_ips:
            if fip['id'] in floating_ip_ids_to_remove:
                ri.floating_ips.remove(fip)
                self.floating_ip_removed(ri, ri.ex_gw_port,
                                         fip['floating_ip_address'],
                                         fip['fixed_ip_address'])
            else:
                # handle remapping of a floating IP
                new_fip = id_to_fip_map[fip['id']]
                new_fixed_ip = new_fip['fixed_ip_address']
                existing_fixed_ip = fip['fixed_ip_address']
                if (new_fixed_ip and existing_fixed_ip and
                        new_fixed_ip != existing_fixed_ip):
                    floating_ip = fip['floating_ip_address']
                    self.floating_ip_removed(ri, ri.ex_gw_port,
                                             floating_ip,
                                             existing_fixed_ip)
                    self.floating_ip_added(ri, ri.ex_gw_port,
                                           floating_ip, new_fixed_ip)
                    ri.floating_ips.remove(fip)
                    ri.floating_ips.append(new_fip)

    def routes_updated(self, ri):
        """Update the state of routes in the router.

         Compares the current routes with the (configured) existing routes
         and detect what was removed or added. Then configure the
         logical router in the hosting device accordingly.
        :param ri: router_info corresponding to the router.
        :return: None
        :raises: neutron.plugins.cisco.l3.common.exceptions.DriverException if
        the configuration operation fails.
        """
        new_routes = ri.router['routes']
        old_routes = ri.routes
        adds, removes = common_utils.diff_list_of_dict(old_routes,
                                                       new_routes)
        for route in adds:
            LOG.debug(_("Added route entry is '%s'"), route)
            # remove replaced route from deleted route
            for del_route in removes:
                if route['destination'] == del_route['destination']:
                    removes.remove(del_route)
                    #replace success even if there is no existing route
            driver = self._drivermgr.get_driver(ri)
            driver.routes_updated(ri, 'replace', route)

        for route in removes:
            LOG.debug(_("Removed route entry is '%s'"), route)
            driver = self._drivermgr.get_driver(ri)
            driver.routes_updated(ri, 'delete', route)
        ri.routes = new_routes

    def _set_subnet_info(self, port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception(
                _("Router port %s has no IP address") % port['id'])
        if len(ips) > 1:
            LOG.error(_("Ignoring multiple IPs on router port %s"),
                      port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)

    def collect_state(self, configurations):
        num_ex_gw_ports = 0
        num_interfaces = 0
        num_floating_ips = 0
        router_infos = self.router_info.values()
        num_routers = len(router_infos)
        num_hd_routers = {}
        routers_per_hd = {}
        for ri in router_infos:
            ex_gw_port = ri.router.get('gw_port')
            if ex_gw_port:
                num_ex_gw_ports += 1
            num_interfaces += len(ri.router.get(
                l3_constants.INTERFACE_KEY, []))
            num_floating_ips += len(ri.router.get(
                l3_constants.FLOATINGIP_KEY, []))
            hd = ri.router['hosting_device']
            if hd:
                num_hd_routers[hd['id']] = num_hd_routers.get(hd['id'], 0) + 1
        for (hd_id, num) in num_hd_routers.items():
            routers_per_hd[hd_id] = {'routers': num}
        non_responding = self._dev_status.get_backlogged_hosting_devices()
        # configurations = self.agent_state['configurations']
        configurations['total routers'] = num_routers
        configurations['total ex_gw_ports'] = num_ex_gw_ports
        configurations['total interfaces'] = num_interfaces
        configurations['total floating_ips'] = num_floating_ips
        configurations['hosting_devices'] = routers_per_hd
        configurations['non_responding_hosting_devices'] = non_responding

    def _sort_resources_per_hosting_device(self, resources):
        """This function will sort the resources on hosting device.

        Syntax of returned dict:
        hosting_devices = {
                            'hd_id1' : {'routers':[routers], 'vpns':[vpns],
                             'fws': fws, 'removed_routers':[routers] }
                            'hd_id2' : {'routers':[routers], 'vpns':[vpns],
                             'fws': fws }
                            .......
                            }
        """
        hosting_devices = {}
        for key in resources.keys():
            for r in resources.get(key) or []:
                hd_id = r['hosting_device']['id']
                hosting_devices.setdefault(hd_id, {})
                hosting_devices[hd_id].setdefault(key, []).append(r)
        return hosting_devices
