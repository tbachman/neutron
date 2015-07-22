import re
import xml.etree.ElementTree as ET
import ciscoconfparse
import netaddr
from neutron.common import constants
from neutron.plugins.cisco.common import cisco_constants

class ConfigValidator(object):
#Compares ASR running-config and neutron DB state, informs caller
#if any configuration was missing from running-config.
    def __init__(router_db_info, hosting_device_info):
        self.hosting_device_info = hosting_device_info
        self.routers = router_db_info

    def check_running_config(self):
        pass

    def populate_segment_nat_dict(self, segment_nat_dict, routers):
        for router in routers:
            if 'hosting_device' not in router:
                continue

            if router['hosting_device']['id'] != hd_id:
                continue

            # Mark which segments have NAT enabled
            # i.e., the segment is present on at least 1 router with
            # both external and internal networks present
            if 'gw_port' in router.keys():
                gw_port = router['gw_port']
                gw_segment_id = gw_port['hosting_info']['segmentation_id']
                if '_interfaces' in router.keys():
                    interfaces = router['_interfaces']
                    for intf in interfaces:
                        if intf['device_owner'] == \
                            constants.DEVICE_OWNER_ROUTER_INTF:
                            intf_segment_id = \
                                              intf['hosting_info']['segmentation_id']
                            segment_nat_dict[gw_segment_id] = True
                            segment_nat_dict[intf_segment_id] = True


    def process_routers_data(self, routers):
        hd_id = self.hosting_device_info['id']
        segment_nat_dict = {}
        conn = self.driver._get_connection()
        running_cfg = self.get_running_config(conn)
        parsed_cfg = ciscoconfparse.CiscoConfParse(running_cfg)

        self.populate_segment_nat_dict(segment_nat_dict, routers)

        for router in routers:
            if 'hosting_device' not in router:
                continue
                
            if router['hosting_device']['id'] != hd_id:
                continue

            missing_cfg = self.check_router(router, parsed_cfg)
            

    def check_router(self, router, running_config):
        if router['role'] == cisco_constants.ROUTER_ROLE_GLOBAL:
            missing_cfg = self.check_global_router(router, running_config)
        else:
            missing_cfg = self.check_tenant_router(router, running_config)
        return missing_cfg

    def check_tenant_router(self, router, running_config):
        # Check VRF
        # Check NAT pool and default route
        # Check ACLs
        # Check floating IPs
        # Check tenant interfaces
        pass

    def check_global_router(self, router, running_config):
        # Check external interfaces
        pass

    def get_vrf_name(self, router):
        short_router_id = router['id'][0:6]
        return "nrouter-%s" % short_router_id

    def get_interface_name_from_hosting_port(self, port):
        """
        generates the underlying subinterface name for a port
        e.g. Port-channel10.200
        """
        vlan = port['hosting_info']['segmentation_id']
        int_prefix = port['hosting_info']['physical_interface']
        return '%s.%s' % (int_prefix, vlan)

    def check_vrf(self, router, running_config):
        missing_cfg = []
        vrf_name = self.get_vrf_name(router)
        vrf_str = "vrf definition %s" % vrf_name
        vrf_substrs = ["address-family ipv4",
                       "address-family ipv6"]
        vrf_cfg = running_config.find_children(vrf_str)
        if not vrf_cfg:
            missing_cfg.append({"cfg":vrf_cfg})
        else:
            for substr in vrf_substrs:
                if substr not in vrf_cfg:
                    missing_cfg.append({"parent":vrf_cfg, "cfg": substr})
        return missing_cfg
    

    def check_nat_pool(self, router, running_config):
        missing_cfg = []

        if 'ex_gw_port' not in router:
            return missing_cfg
        gw_port = router['ex_gw_port']

        vrf_name = self.get_vrf_name(router)
        pool_name = "%s_nat_pool" % (vrf_name)
        pool_info = gw_port['nat_pool_info']
        pool_ip = pool_info['pool_ip']
        pool_net = netaddr.IPNetwork(pool_info['pool_cidr'])
        nat_pool_str = "ip nat pool %s %s %s netmask %s" % (pool_name,
                                                            pool_ip,
                                                            pool_ip,
                                                            pool_net.netmask)
        
        pool_cfg = running_config.find_lines(nat_pool_str)
        if not pool_cfg:
            missing_cfg.append({"cfg":nat_pool_str})

        if "_interfaces" in router:
            interfaces = router['_interfaces']
            for intf in interfaces:
                segment_id = intf['hosting_info']['segmentation_id']
                acl_name = "neutron_acl_%s" % segment_id
                nat_overload_str = "ip nat inside source list %s pool %s vrf %s overload"
                nat_overload_str = nat_overload_str % (acl_name,
                                                       pool_name,
                                                       vrf_name)
                overload_cfg = running_config.find_lines(nat_overload_str)
                if not overload_cfg:
                    missing_cfg.append({"cfg":nat_overload_str})

        return missing_cfg
        
    def check_default_route(self, router, running_config):
        missing_cfg = []

        if 'ex_gw_port' not in router:
            return missing_cfg
            
        vrf_name = self.get_vrf_name(router)

        gw_port = router['ex_gw_port']
        ext_gw_ip = gw_port['subnets'][0]['gateway_ip']

        intf_name = self._get_interface_name_from_hosting_port(gw_port)

        
        route_str = "ip route vrf %s 0.0.0.0 0.0.0.0 %s %s" % (vrf_name,
                                                               intf_name,
                                                               ext_gw_ip)

        route_cfg = running_config.find_lines(route_str)
        if not route_cfg:
            missing_cfg.append({"cfg":route_str})

        return missing_cfg

        
    def check_acls(self, router, running_config):
        pass
        
    def check_fips(self, router, running_config):
        pass

    def check_interfaces(self, router, running_config):
        pass

    def check_ext_interfaces(self, router, running_config):
        pass
