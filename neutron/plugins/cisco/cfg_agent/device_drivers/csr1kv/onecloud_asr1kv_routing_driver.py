import logging
import netaddr
import re
import time
import xml.etree.ElementTree as ET

import ciscoconfparse
from ncclient import manager

from oslo.config import cfg

from neutron.plugins.cisco.cfg_agent import cfg_exceptions as cfg_exc
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (
    cisco_csr1kv_snippets as snippets)
from neutron.plugins.cisco.cfg_agent.device_drivers.csr1kv import (csr1kv_routing_driver as csr1kv_driver)

LOG = logging.getLogger(__name__)


############################################################
# override some CSR1kv methods to work with physical ASR1k #
############################################################
class ASR1kConfigInfo(object):
    """ASR1k Driver Cisco Configuration class."""

    def __init__(self, **device_params):
        self.asr_dict = {}
        self.asr_list = None
        self._create_asr_device_dictionary(device_params)

    # def _create_asr_device_dictionary(self):
    #     """Create the ASR device cisco dictionary.
    #
    #     Read data from the cisco_router_plugin.ini device supported sections.
    #     """
    #     multi_parser = cfg.MultiConfigParser()
    #     read_ok = multi_parser.read(cfg.CONF.config_file)
    #
    #     if len(read_ok) != len(cfg.CONF.config_file):
    #         raise cfg.Error(_("Some config files were not parsed properly"))
    #
    #     asr_count = 0
    #     for parsed_file in multi_parser.parsed:
    #         for parsed_item in parsed_file.keys():
    #             dev_id, sep, dev_ip = parsed_item.partition(':')
    #             if dev_id.lower() == 'asr':
    #                 if dev_ip not in self.asr_dict:
    #                     self.asr_dict[dev_ip] = {}
    #
    #                 asr_entry = self.asr_dict[dev_ip]
    #                 asr_entry['ip'] = dev_ip
    #                 asr_entry['conn'] = None
    #
    #                 for dev_key, value in parsed_file[parsed_item].items():
    #                     asr_entry[dev_key] = value[0]
    #
    #                 asr_entry['order'] = int(asr_entry['order'])
    #
    #     LOG.error("ASR dict: %s" % self.asr_dict)

    def _create_asr_device_dictionary(self, device_params):
        """Create the ASR device cisco dictionary."""
        asr_entry = {}
        asr_entry['ip'] = device_params['management_ip_address']
        asr_entry['conn'] = None
        asr_entry['ssh_port'] = device_params['protocol_port']
        asr_entry['username'] = device_params['credentials']['username']
        asr_entry['password'] = device_params['credentials']['password']
        asr_entry['order'] = int(device_params['order'])
        self.asr_dict[device_params['management_ip_address']] = asr_entry
        LOG.error("ASR dict: %s" % self.asr_dict)

    def get_first_asr(self):
        return self.asr_dict.values()[0]

    def get_asr_list(self):
        if self.asr_list is None:
            self.asr_list = sorted(self.asr_dict.values(),
                                   key=lambda ent:ent['order'])

        return self.asr_list




class ASR1kRoutingDriver(csr1kv_driver.CSR1kvRoutingDriver):

    def __init__(self, **device_params):
        self._asr_config = ASR1kConfigInfo(**device_params)
        self._csr_conn = None
        self._intfs_enabled = False
        self.ignore_cfg_check = True
        self.hsrp_group_base = 200
        self.hsrp_real_ip_base = 200
        return

    def _get_asr_list(self):
        return self._asr_config.get_asr_list()




    ###### Public Functions ########

    def internal_network_added(self, ri, port):
        self._csr_create_subinterface(ri, port, False)

    def external_gateway_added(self, ri, ex_gw_port):
        ex_gw_ip = ex_gw_port['subnet']['gateway_ip']
        self._csr_create_subinterface(ri, ex_gw_port, True, ex_gw_ip)
        if ex_gw_ip:
            # Set default route via this network's gateway ip
            self._csr_add_default_route(ri, ex_gw_ip)





    ###### Internal "Preparation" Functions ########

    def _csr_create_subinterface(self, ri, port, is_external=False, gw_ip=""):
        vrf_name = self._csr_get_vrf_name(ri)
        ip_cidr = port['ip_cidr']
        netmask = netaddr.IPNetwork(ip_cidr).netmask

        if is_external is True:
            gateway_ip = gw_ip
        else:
            gateway_ip = ip_cidr.split('/')[0]

        vlan = self._get_interface_vlan_from_hosting_port(port)

        for asr_ent in self._get_asr_list():
            tmp_ip = netaddr.IPAddress(gateway_ip)
            tmp_ip = tmp_ip.__add__(asr_ent['order'] + self.hsrp_real_ip_base) # increment IP addr by count to get real HSRP ips
            tmp_ip = str(tmp_ip)

            subinterface = self._get_interface_name_from_hosting_port(port, asr_ent)
            self._create_subinterface(subinterface, vlan, vrf_name,
                                      tmp_ip, netmask, asr_ent, is_external)

            self._csr_add_ha_HSRP(ri, port, gateway_ip, is_external) # Always do HSRP


    def _csr_remove_subinterface(self, port):
        for asr_ent in self._get_asr_list():
            subinterface = self._get_interface_name_from_hosting_port(port, asr_ent)
            self._remove_subinterface(subinterface, asr_ent)


    def _csr_add_internalnw_nat_rules(self, ri, port, ex_port):
        vrf_name = self._csr_get_vrf_name(ri)
        in_vlan = self._get_interface_vlan_from_hosting_port(port)
        acl_no = 'acl_' + str(in_vlan)
        internal_cidr = port['ip_cidr']
        internal_net = netaddr.IPNetwork(internal_cidr).network
        netmask = netaddr.IPNetwork(internal_cidr).hostmask

        for asr_ent in self._get_asr_list():
            inner_intfc = self._get_interface_name_from_hosting_port(port, asr_ent)
            outer_intfc = self._get_interface_name_from_hosting_port(ex_port, asr_ent)
            self._nat_rules_for_internet_access(acl_no, internal_net,
                                                netmask, inner_intfc,
                                                outer_intfc, vrf_name, asr_ent)

    def _csr_remove_internalnw_nat_rules(self, ri, ports, ex_port):

        for asr_ent in self._get_asr_list():

            acls = []
            #First disable nat in all inner ports
            for port in ports:
                in_intfc_name = self._get_interface_name_from_hosting_port(port, asr_ent)
                inner_vlan = self._get_interface_vlan_from_hosting_port(port)
                acls.append("acl_" + str(inner_vlan))
                self._remove_interface_nat(in_intfc_name, 'inside', asr_ent)

                #Wait for two second
                LOG.debug("Sleep for 2 seconds before clearing NAT rules")
                time.sleep(2)

                #Clear the NAT translation table
                self._remove_dyn_nat_translations(asr_ent)

                # Remove dynamic NAT rules and ACLs
                vrf_name = self._csr_get_vrf_name(ri)
                ext_intfc_name = self._get_interface_name_from_hosting_port(ex_port, asr_ent)
                for acl in acls:
                    self._remove_dyn_nat_rule(acl, ext_intfc_name, vrf_name, asr_ent)


    def _csr_add_default_route(self, ri, gw_ip):
        return # disable for now until next_hop issue resolved
        vrf_name = self._csr_get_vrf_name(ri)
        for asr_ent in self._get_asr_list():
            self._add_default_static_route(gw_ip, vrf_name, asr_ent)

    def _csr_remove_default_route(self, ri, gw_ip):
        return # disable for now
        vrf_name = self._csr_get_vrf_name(ri)
        for asr_ent in self._get_asr_list():
            self._remove_default_static_route(gw_ip, vrf_name, asr_ent)

    def _csr_add_floating_ip(self, ri, ex_gw_port, floating_ip, fixed_ip):
        vrf_name = self._csr_get_vrf_name(ri)
        for asr_ent in self._get_asr_list():
            self._add_floating_ip(floating_ip, fixed_ip, vrf_name, asr_ent, ex_gw_port)

    def _csr_remove_floating_ip(self, ri, ex_gw_port, floating_ip, fixed_ip):
        vrf_name = self._csr_get_vrf_name(ri)

        for asr_ent in self._get_asr_list():
            out_intfc_name = self._get_interface_name_from_hosting_port(ex_gw_port, asr_ent)
            # First remove NAT from outer interface
            self._remove_interface_nat(out_intfc_name, 'outside', asr_ent)
            #Clear the NAT translation table
            self._remove_dyn_nat_translations(asr_ent)
            #Remove the floating ip
            self._remove_floating_ip(floating_ip, fixed_ip, vrf_name, asr_ent, ex_gw_port)
            #Enable NAT on outer interface
            self._add_interface_nat(out_intfc_name, 'outside', asr_ent)

    def _csr_update_routing_table(self, ri, action, route):
        vrf_name = self._csr_get_vrf_name(ri)
        destination_net = netaddr.IPNetwork(route['destination'])
        dest = destination_net.network
        dest_mask = destination_net.netmask
        next_hop = route['nexthop']

        for asr_ent in self._get_asr_list():
            if action is 'replace':
                self._add_static_route(dest, dest_mask, next_hop, vrf_name, asr_ent)
            elif action is 'delete':
                self._remove_static_route(dest, dest_mask, next_hop, vrf_name, asr_ent)
            else:
                LOG.error(_('Unknown route command %s'), action)

    def _csr_create_vrf(self, ri):
        vrf_name = self._csr_get_vrf_name(ri)
        for asr_ent in self._get_asr_list():
            self._create_vrf(vrf_name, asr_ent)

    def _csr_remove_vrf(self, ri):
        vrf_name = self._csr_get_vrf_name(ri)
        for asr_ent in self._get_asr_list():
            self._remove_vrf(vrf_name, asr_ent)

    def _csr_add_ha_HSRP(self, ri, port, ip, is_external=False):
        vlan = self._get_interface_vlan_from_hosting_port(port)
        group = vlan
        vrf_name = self._csr_get_vrf_name(ri)

        for asr_ent in self._get_asr_list():
            priority = asr_ent['order']
            subinterface = self._get_interface_name_from_hosting_port(port, asr_ent)
            self._set_ha_HSRP(subinterface, vrf_name, priority, group, ip, asr_ent, is_external)



    ###### Internal "Action" Functions ########

    def _create_subinterface(self, subinterface, vlan_id, vrf_name, ip, mask, asr_ent, is_external=False):
        if vrf_name not in self._get_vrfs(asr_ent):
            LOG.error(_("VRF %s not present"), vrf_name)
        if is_external is True:
            confstr = snippets.CREATE_SUBINTERFACE_EXTERNAL % (subinterface, vlan_id,
                                                               ip, mask)
        else:
            confstr = snippets.CREATE_SUBINTERFACE % (subinterface, vlan_id,
                                                      vrf_name, ip, mask)

        self._edit_running_config(confstr, 'CREATE_SUBINTERFACE', asr_ent)

    def _remove_subinterface(self, subinterface, asr_ent):
        #Optional : verify this is the correct subinterface
        if self._interface_exists(subinterface, asr_ent) or self.ignore_cfg_check:
            confstr = snippets.REMOVE_SUBINTERFACE % subinterface
            self._edit_running_config(confstr, 'REMOVE_SUBINTERFACE', asr_ent)


    def _nat_rules_for_internet_access(self, acl_no, network,
                                       netmask,
                                       inner_intfc,
                                       outer_intfc,
                                       vrf_name, asr_ent):
        """Configure the NAT rules for an internal network.

           refer to comments in parent class
        """
        conn = self._get_connection(asr_ent)
        # Duplicate ACL creation throws error, so checking
        # it first. Remove it in future as this is not common in production
        acl_present = self._check_acl(acl_no, network, netmask, asr_ent)
        if not acl_present:
            confstr = snippets.CREATE_ACL % (acl_no, network, netmask)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            self._check_response(rpc_obj, 'CREATE_ACL')

        confstr = snippets.SET_DYN_SRC_TRL_INTFC % (acl_no, inner_intfc,
                                                    vrf_name)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'CREATE_SNAT')

        confstr = snippets.SET_NAT % (inner_intfc, 'inside')
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_NAT')

        confstr = snippets.SET_NAT % (outer_intfc, 'outside')
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_NAT')


    def _add_interface_nat(self, intfc_name, intfc_type, asr_ent):
        conn = self._get_connection(asr_ent)
        confstr = snippets.SET_NAT % (intfc_name, intfc_type)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_NAT ' + intfc_type)

    def _remove_interface_nat(self, intfc_name, intfc_type, asr_ent):
        conn = self._get_connection(asr_ent)
        confstr = snippets.REMOVE_NAT % (intfc_name, intfc_type)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'REMOVE_NAT ' + intfc_type)

    def _remove_dyn_nat_rule(self, acl_no, outer_intfc_name, vrf_name, asr_ent):
        conn = self._get_connection(asr_ent)
        confstr = snippets.SNAT_CFG % (acl_no, outer_intfc_name, vrf_name)
        if self._cfg_exists(confstr, asr_ent) or self.ignore_cfg_check:
            confstr = snippets.REMOVE_DYN_SRC_TRL_INTFC % (acl_no,
                                                           outer_intfc_name,
                                                           vrf_name)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            self._check_response(rpc_obj, 'REMOVE_DYN_SRC_TRL_INTFC')

        confstr = snippets.REMOVE_ACL % acl_no
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'REMOVE_ACL')

    def _remove_dyn_nat_translations(self, asr_ent):
        conn = self._get_connection(asr_ent)
        confstr = snippets.CLEAR_DYN_NAT_TRANS
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'CLEAR_DYN_NAT_TRANS')

    def _add_floating_ip(self, floating_ip, fixed_ip, vrf, asr_ent, ex_gw_port):
        """
        To implement a floating ip, an ip static nat is configured in the underlying router
        ex_gw_port contains data to derive the vlan associated with related subnet for the
        fixed ip.  The vlan in turn is applied to the redundancy parameter for setting the
        IP NAT.
        """
        conn = self._get_connection(asr_ent)
        vlan = ex_gw_port['hosting_info']['segmentation_id']

        confstr = snippets.SET_STATIC_SRC_TRL_NO_VRF_MATCH % (fixed_ip, floating_ip, vrf, vlan)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_STATIC_SRC_TRL')

    def _remove_floating_ip(self, floating_ip, fixed_ip, vrf, asr_ent,ex_gw_port):
        conn = self._get_connection(asr_ent)
        vlan = ex_gw_port['hosting_info']['segmentation_id']

        confstr = snippets.REMOVE_STATIC_SRC_TRL_NO_VRF_MATCH % (fixed_ip, floating_ip, vrf, vlan)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'REMOVE_STATIC_SRC_TRL')

    def _add_static_route(self, dest, dest_mask, next_hop, vrf, asr_ent):
        conn = self._get_connection(asr_ent)
        confstr = snippets.SET_IP_ROUTE % (vrf, dest, dest_mask, next_hop)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'SET_IP_ROUTE')

    def _remove_static_route(self, dest, dest_mask, next_hop, vrf, asr_ent):
        conn = self._get_connection(asr_ent)
        confstr = snippets.REMOVE_IP_ROUTE % (vrf, dest, dest_mask, next_hop)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, 'REMOVE_IP_ROUTE')

    def _add_default_static_route(self, gw_ip, vrf, asr_ent):
        conn = self._get_connection(asr_ent)
        confstr = snippets.DEFAULT_ROUTE_CFG % (vrf, gw_ip)
        if not self._cfg_exists(confstr, asr_ent):
            confstr = snippets.SET_DEFAULT_ROUTE % (vrf, gw_ip)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            self._check_response(rpc_obj, 'SET_DEFAULT_ROUTE')

    def _remove_default_static_route(self, gw_ip, vrf, asr_ent):
        conn = self._get_connection(asr_ent)
        confstr = snippets.DEFAULT_ROUTE_CFG % (vrf, gw_ip)
        if self._cfg_exists(confstr, asr_ent) or self.ignore_cfg_check:
            confstr = snippets.REMOVE_DEFAULT_ROUTE % (vrf, gw_ip)
            rpc_obj = conn.edit_config(target='running', config=confstr)
            self._check_response(rpc_obj, 'REMOVE_DEFAULT_ROUTE')

    def _set_ha_HSRP(self, subinterface, vrf_name, priority, group, ip, asr_ent, is_external=False):
        if vrf_name not in self._get_vrfs(asr_ent):
            LOG.error(_("VRF %s not present"), vrf_name)

        if is_external is True:
            confstr = snippets.SET_INTC_ASR_HSRP_EXTERNAL % (subinterface, group,
                                                             priority, group, ip,
                                                             group, group, group, group)
        else:
            confstr = snippets.SET_INTC_ASR_HSRP % (subinterface, vrf_name, group,
                                                    priority, group, ip,
                                                    group, group, group, group)

        action = "SET_INTC_HSRP (Group: %s, Priority: % s)" % (group, priority)
        self._edit_running_config(confstr, action, asr_ent)

    def _remove_ha_HSRP(self, subinterface, group, asr_ent):
        confstr = snippets.REMOVE_INTC_HSRP % (subinterface, group)
        action = ("REMOVE_INTC_HSRP (subinterface:%s, Group:%s)"
                  % (subinterface, group))
        self._edit_running_config(confstr, action, asr_ent)


    def _create_vrf(self, vrf_name, asr_ent):
        try:
            conn = self._get_connection(asr_ent)
            confstr = snippets.CREATE_VRF % vrf_name
            rpc_obj = conn.edit_config(target='running', config=confstr)
            if self._check_response(rpc_obj, 'CREATE_VRF'):
                LOG.info(_("VRF %s successfully created"), vrf_name)
        except Exception:
            LOG.exception(_("Failed creating VRF %s"), vrf_name)

    def _remove_vrf(self, vrf_name, asr_ent):
        if vrf_name in self._get_vrfs(asr_ent) or self.ignore_cfg_check:
            conn = self._get_connection(asr_ent)
            confstr = snippets.REMOVE_VRF % vrf_name
            rpc_obj = conn.edit_config(target='running', config=confstr)
            if self._check_response(rpc_obj, 'REMOVE_VRF'):
                LOG.info(_("VRF %s removed"), vrf_name)
        else:
            LOG.warning(_("VRF %s not present"), vrf_name)


    def _get_vrfs(self, asr_ent):
        """Get the current VRFs configured in the device.

        :return: A list of vrf names as string
        """
        vrfs = []
        ioscfg = self._get_running_config(asr_ent)
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        vrfs_raw = parse.find_lines("^ip vrf")
        for line in vrfs_raw:
            #  raw format ['ip vrf <vrf-name>',....]
            vrf_name = line.strip().split(' ')[2]
            vrfs.append(vrf_name)
        LOG.info(_("VRFs:%s"), vrfs)
        return vrfs

    def _cfg_exists(self, cfg_str, asr_ent):
        """Check a partial config string exists in the running config.

        :param cfg_str: config string to check
        :return : True or False
        """
        ioscfg = self._get_running_config(asr_ent)
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        cfg_raw = parse.find_lines("^" + cfg_str)
        LOG.debug("_cfg_exists(): Found lines %s", cfg_raw)
        return len(cfg_raw) > 0

    def _interface_exists(self, interface, asr_ent):
        """Check whether interface exists."""
        ioscfg = self._get_running_config(asr_ent)
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        intfs_raw = parse.find_lines("^interface " + interface)
        return len(intfs_raw) > 0

    def _check_acl(self, acl_no, network, netmask, asr_ent):
        """Check a ACL config exists in the running config.

        :param acl_no: access control list (ACL) number
        :param network: network which this ACL permits
        :param netmask: netmask of the network
        :return:
        """
        exp_cfg_lines = ['ip access-list standard ' + str(acl_no),
                         ' permit ' + str(network) + ' ' + str(netmask)]
        ioscfg = self._get_running_config(asr_ent)
        parse = ciscoconfparse.CiscoConfParse(ioscfg)
        acls_raw = parse.find_children(exp_cfg_lines[0])
        if acls_raw:
            if exp_cfg_lines[1] in acls_raw:
                return True
            LOG.error(_("Mismatch in ACL configuration for %s"), acl_no)
            return False
        LOG.debug("%s is not present in config", acl_no)
        return False

    def _edit_running_config(self, confstr, snippet, asr_ent):
        conn = self._get_connection(asr_ent)
        rpc_obj = conn.edit_config(target='running', config=confstr)
        self._check_response(rpc_obj, snippet)

    def _get_running_config(self, asr_ent):
        """Get the CSR's current running config.

        :return: Current IOS running config as multiline string
        """
        conn = self._get_connection(asr_ent)
        config = conn.get_config(source="running")
        if config:
            root = ET.fromstring(config._raw)
            running_config = root[0][0]
            rgx = re.compile("\r*\n+")
            ioscfg = rgx.split(running_config.text)
            return ioscfg



    ###### Internal "Support" Functions ########

    def _get_interface_name_from_hosting_port(self, port, asr_ent):
        vlan = self._get_interface_vlan_from_hosting_port(port)
        subinterface = asr_ent['target_intf']
        intfc_name = "%s.%s" % (subinterface, vlan)
        return intfc_name

    def _get_connection(self, asr_ent):
        """Make SSH connection to the CSR.

           refer to comments in parent class
        """

        asr_host = asr_ent['ip']
        asr_ssh_port = asr_ent['ssh_port']
        asr_user = asr_ent['username']
        asr_password = asr_ent['password']
        self._timeout = 30

        try:
            asr_conn = asr_ent['conn']
            if asr_conn and asr_conn.connected:
                return asr_conn
            else:
                asr_conn = manager.connect(host=asr_host,
                                           port=asr_ssh_port,
                                           username=asr_user,
                                           password=asr_password,
                                           allow_agent=False,
                                           look_for_keys=False,
                                           #unknown_host_cb=lambda host,
                                           # fingerprint: True,
                                           device_params={'name': "csr"},
                                           timeout=self._timeout)
                if not self._intfs_enabled:
                    #self._intfs_enabled = self._enable_intfs(self._csr_conn)
                    self._intfs_enabled = True

                asr_ent['conn'] = asr_conn

            return asr_conn
        except Exception as e:
            conn_params = {'host': asr_host, 'port': asr_ssh_port,
                           'user': asr_user,
                           'timeout': self._timeout, 'reason': e.message}
            raise cfg_exc.CSR1kvConnectionException(**conn_params)


'''
NOTES, TODO:

Version:
* 15-Dec-2014: Base file copied from Onecloud repo. branch:'icehouse_hsrp'

Existing notes:
--------------

We need to configure multiple ASRs, current code expects one "connection"
on which the code can call get_config, edit_config


http://tools.ietf.org/html/rfc6241#appendix-E.2
Netconf doesn't really have multi-node transcations built-in
Need to config lock the nodes, apply config, and then deal with partial failure
  i.e. retry later or undo the partial config, then release cfg locks

'''