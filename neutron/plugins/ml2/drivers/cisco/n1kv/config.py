# Copyright 2014 OpenStack Foundation
# All rights reserved.
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

from oslo.config import cfg


n1kv_opts = [
    cfg.StrOpt('default_vlan_network_profile', default='default-vlan-np',
               help=_("Cisco Nexus1000V default network profile for VLAN "
                      "networks")),
    cfg.StrOpt('default_vxlan_network_profile', default='default-vxlan-np',
               help=_("Cisco Nexus1000V default network profile for VXLAN "
                      "networks")),
    cfg.StrOpt('default_policy_profile', default='default-pp',
               help=_("Cisco Nexus1000V default policy profile")),
    cfg.BoolOpt('restrict_policy_profiles', default=False,
               help=_("Restrict the visibility of policy profiles to the "
                      "tenants")),
    cfg.IntOpt('poll_duration', default=60,
               help=_("Cisco Nexus1000V policy profile polling duration in "
                      "seconds")),
    cfg.IntOpt('http_pool_size', default=4,
               help=_("Number of threads to use to make HTTP requests")),
    cfg.IntOpt('http_timeout', default=15,
               help=_("HTTP timeout, in seconds, for connections to the "
                      "Nexus1000V VSM")),
    cfg.IntOpt('sync_interval', default=300,
               help=_("Time interval between consecutive neutron-VSM syncs ")),

]


cfg.CONF.register_opts(n1kv_opts, "ml2_cisco_n1kv")

# Format for n1kv_dict is:
# {'<device ipaddr>': {'<keyword>': '<value>', ...}}
#
# Example:
# {'1.1.1.1': {'username': 'admin',
#  'password': 'mySecretPassword'},
#  '1.1.1.2': {'username': 'admin',
#  'password': 'mySecretPassword'}}


class ML2CiscoN1kvConfig(object):
    """Cisco N1KV ML2 Driver Cisco Configuration class."""
    n1kv_dict = {}

    def __init__(self):
        self._create_ml2_cisco_n1kv_vsm_dictionary()

    def _create_ml2_cisco_n1kv_vsm_dictionary(self):
        """Create the ML2 device cisco n1kv dictionary.

        Read data from the ml2_conf_cisco.ini device supported sections.
        """
        multi_parser = cfg.MultiConfigParser()
        read_ok = multi_parser.read(cfg.CONF.config_file)

        if len(read_ok) != len(cfg.CONF.config_file):
            raise cfg.Error(_("Some config files were not parsed properly"))

        for parsed_file in multi_parser.parsed:
            for parsed_item in parsed_file.keys():
                dev_id, sep, vsm_ip = parsed_item.partition(':')
                if dev_id.lower() == 'ml2_cisco_n1kv_vsm':
                    for dev_key, value in parsed_file[parsed_item].items():
                        if vsm_ip not in self.n1kv_dict:
                            self.n1kv_dict[vsm_ip] = {}
                        self.n1kv_dict[vsm_ip][dev_key] = value[0]

    def get_n1kv_dict(self):
        return self.n1kv_dict
