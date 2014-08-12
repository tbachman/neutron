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

"""Interim code to obtain router information for Cisco CSR

This obtains information on the Cisco CSR router from an INI file. This is
an interim solution, until the Cisco L3 router plugin code is up-streamed.
Once that happens, this code and UTs will be removed and the API calls to
the L3 router will be used.

To use this code, the Neutron server is started with a config_file that
points to an INI file with router configuration. The router would be created
(manually) in Nova, the INI file is then updated with the router information,
and then VPN IPSec site-to-site connections can be created using that router.
"""

import netaddr
import re

from oslo.config import cfg

from neutron.db import l3_db
from neutron.db import models_v2
from neutron.openstack.common.gettextutils import _LE
from neutron.openstack.common.gettextutils import _LI
from neutron.openstack.common import log as logging
from neutron.services.vpn.device_drivers import (
    cisco_csr_rest_client as csr_client)


LOG = logging.getLogger(__name__)
mgmt_intf_re = re.compile(r'^GigabitEthernet[123]')


def get_available_csrs_from_config(config_files):
    """Read INI for available Cisco CSRs that driver can use.

    Loads management port, tunnel IP, user, and password information for
    available CSRs from configuration file. Driver will use this info to
    configure VPN connections. The CSR is associated 1:1 with a Neutron
    router. To identify which CSR to use for a VPN service, the public
    (GW) IP of the Neutron router will be used as an index into the CSR
    config info.
    """
    multi_parser = cfg.MultiConfigParser()
    LOG.info(_LI("Scanning config files %s for Cisco CSR configurations"),
             config_files)
    try:
        read_ok = multi_parser.read(config_files)
    except cfg.ParseError as pe:
        LOG.error(_LE("Config file parse error: %s"), pe)
        return {}

    if len(read_ok) != len(config_files):
        raise cfg.Error(_("Unable to parse config files %s for Cisco CSR "
                          "info") % config_files)
    csrs_found = {}
    for parsed_file in multi_parser.parsed:
        for parsed_item in parsed_file.keys():
            device_type, sep, for_router = parsed_item.partition(':')
            if device_type.lower() == 'cisco_csr_rest':
                try:
                    netaddr.IPNetwork(for_router)
                except netaddr.core.AddrFormatError:
                    LOG.error(_LE("Ignoring Cisco CSR configuration entry - "
                                  "router IP %s is not valid"), for_router)
                    continue
                entry = parsed_file[parsed_item]
                # Check for missing fields
                try:
                    rest_mgmt_ip = entry['rest_mgmt'][0]
                    tunnel_ip = entry['tunnel_ip'][0]
                    username = entry['username'][0]
                    password = entry['password'][0]
                    host = entry['host'][0]
                    mgmt_intf = entry['mgmt_intf'][0]
                except KeyError as ke:
                    LOG.error(_LE("Ignoring Cisco CSR for router %(router)s "
                                  "- missing %(field)s setting"),
                              {'router': for_router, 'field': str(ke)})
                    continue
                # Validate fields
                try:
                    timeout = float(entry['timeout'][0])
                except ValueError:
                    LOG.error(_LE("Ignoring Cisco CSR for router %s - "
                                  "timeout is not a floating point number"),
                              for_router)
                    continue
                except KeyError:
                    timeout = csr_client.TIMEOUT
                m = mgmt_intf_re.match(mgmt_intf)
                if not m:
                    LOG.error(_LE("Malformed management interface name for "
                                  "Cisco CSR router entry - %s"), mgmt_intf)
                    continue
                try:
                    netaddr.IPAddress(rest_mgmt_ip)
                except netaddr.core.AddrFormatError:
                    LOG.error(_("Ignoring Cisco CSR for subnet %s - "
                                "REST management is not an IP address"),
                              for_router)
                    continue
                try:
                    netaddr.IPAddress(tunnel_ip)
                except netaddr.core.AddrFormatError:
                    LOG.error(_LE("Ignoring Cisco CSR for router %s - "
                                  "local tunnel is not an IP address"),
                              for_router)
                    continue
                m = mgmt_intf_re.match(mgmt_intf)
                if not m:
                    LOG.error(_LE("Malformed management interface name for "
                                  "Cisco CSR router entry - %s"), mgmt_intf)
                    continue
                csrs_found[for_router] = {'rest_mgmt_ip': rest_mgmt_ip,
                                          'tunnel_ip': tunnel_ip,
                                          'username': username,
                                          'password': password,
                                          'host': host,
                                          'mgmt_intf': mgmt_intf,
                                          'timeout': timeout}

                LOG.debug("Found CSR for router %(router)s: %(info)s",
                          {'router': for_router,
                           'info': csrs_found[for_router]})
    return csrs_found


def _get_router_id_via_external_ip(context, external_ip):
    '''Find router ID for router with matching GW port IP.'''
    query = context.session.query(l3_db.Router.id)
    query = query.join(models_v2.Port,
                       l3_db.Router.gw_port == models_v2.Port.id)
    query = query.filter(
        models_v2.Port.fixed_ips[0]['ip_address'] == external_ip)
    return query.first()


def get_active_routers_for_host(context, host):
    '''Get list of routers from INI file that use host requested.'''
    configured_routers = get_available_csrs_from_config(cfg.CONF.config_file)
    routers = []
    for router_ip, info in configured_routers.items():
        if host == info['host']:
            router_id = _get_router_id_via_external_ip(context, router_ip)
            if router_id:
                routers.append({
                    'id': router_id,
                    'hosting_device': {
                        'management_ip_address': info['rest_mgmt_ip'],
                        'credentials': {'username': info['username'],
                                        'password': info['password']}
                    },
                    'mgmt_intf': info['mgmt_intf']
                })
    return routers


def _get_external_ip_for_router(context, router_id):
    '''Find port that is the gateway port for router.'''
    query = context.session.query(models_v2.Port.fixed_ips)
    query = query.join(l3_db.Router,
                       l3_db.Router.gw_port == models_v2.Port.id)
    gw_port = query.first()
    if gw_port:
        return gw_port[0]['ip_address']


def get_host_for_router(context, router_id):
    '''Find out GW port for router and look-up in INI file to get host.'''
    routers = get_available_csrs_from_config(cfg.CONF.config_file)
    router_public_ip = _get_external_ip_for_router(context, router_id)
    if router_public_ip:
        router = routers.get(router_public_ip)
        if router:
            LOG.debug("PCM: Found host %(host)s for router %(router)s",
                      {'host': router['host'], 'router': router_id})
            return router['host']
    LOG.debug("PCM: Unable to find host for router %s", router_id)
    return ''
