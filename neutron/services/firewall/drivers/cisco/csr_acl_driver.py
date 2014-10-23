# Copyright 2014 Cisco Systems, Inc.
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

import requests

from neutron.openstack.common import log as logging
from neutron.services.firewall.drivers import fwaas_base
from neutron.services.vpn.device_drivers import cisco_csr_rest_client

LOG = logging.getLogger(__name__)

#----- ACL REST URL definitions -------------------------------------------
ACL_API = 'acl'
ACL_API_ACLID = 'acl/%s'                            # ACLID
ACL_API_ACLID_IF = 'acl/%s/interfaces'              # ACLID
ACL_API_ACLID_IFID_DIR = 'acl/%s/interfaces/%s_%s'  # ACLID, IF_DIR


class CsrAclDriver(fwaas_base.FwaasDriverBase):
    """Cisco CSR ACL driver for FWaaS.

    This driver will send ACL configuration via RESTAPI to CSR1kv.
    This driver will return error to the caller function in case of
    error such as validation failures, sending configuration failuers.
    The caller function will handle the error return properly.
    """

    def __init__(self):
        LOG.debug("CsrAclDriver: Initializing fwaas CSR ACL driver")

    def _get_csr_host(self, fw_v_ext):
        settings = {
            'rest_mgmt_ip': fw_v_ext['host_mngt_ip'],
            'username': fw_v_ext['host_usr_nm'],
            'password': fw_v_ext['host_usr_pw'],
            'timeout': 30,
        }
        return cisco_csr_rest_client.CsrRestClient(settings)

    def _validate_fw_rule_data(self, fw):
        LOG.debug("CsrAcl _validate_fw_rule_data: fw %s", fw['id'])
        if 'firewall_rule_list' not in fw:
            LOG.debug("ERROR: no rule list")
            return False
        rlist = fw['firewall_rule_list']
        for r in rlist:
            if 'name' not in r:
                LOG.debug("ERROR: no rule name")
                return False
            if r.get('ip_version', '') != 4:
                LOG.debug("ERROR: invalid ip version in rule [%s]", r['name'])
                return False
            if 'protocol' not in r:
                LOG.debug("ERROR: no protocol in rule [%s]", r['name'])
                return False
            if r.get('action', '').lower() not in ('allow', 'deny'):
                LOG.debug("ERROR: invalid action in rule [%s]", r['name'])
                return False

        return True

    def _validate_fw_data(self, fw):
        LOG.debug("CsrAcl _validate_fw_data: fw %s", fw['id'])
        if 'admin_state_up' not in fw:
            LOG.debug("ERROR: no admin_state_up")
            return False
        if 'vendor_ext' not in fw:
            LOG.debug("ERROR: no ventor ext")
            return False
        v_ext = fw['vendor_ext']
        if 'host_mngt_ip' not in v_ext:
            LOG.debug("ERROR: no host_mngt_ip")
            return False
        if 'host_usr_nm' not in v_ext:
            LOG.debug("ERROR: no host_usr_nm")
            return False
        if 'host_usr_pw' not in v_ext:
            LOG.debug("ERROR: no host_usr_pw")
            return False
        if 'if_list' not in v_ext:
            LOG.debug("ERROR: no if_list")
            return False

        fw_if_list = v_ext['if_list']
        for fw_if in fw_if_list:
            if fw_if.get('direction', '') not in ('inside', 'outside', 'both'):
                LOG.debug("ERROR: invalid direction")
                return False
            if 'port' not in fw_if:
                LOG.debug("ERROR: no port")
                return False
            port = fw_if['port']
            if 'id' not in port:
                LOG.debug("ERROR: no port id")
                return False
            if 'hosting_info' not in port:
                LOG.debug("ERROR: no hosting_info")
                return False
            if 'segmentation_id' not in port['hosting_info']:
                LOG.debug("ERROR: no segmentation_id")
                return False
            if 'hosting_port_name' not in port['hosting_info']:
                LOG.debug("ERROR: hosting_port_name")
                return False
            _name = port['hosting_info']['hosting_port_name']
            if_type = _name.split(':')[0] + ':'
            if if_type not in ('t1_p:', 't2_p:'):
                LOG.debug("ERROR: invalide interface type")
                return False

        return True

    def _get_acl_rule_data(self, fw):
        """Get ACL RESTAPI request data from firewall dictionary.

        :return: ACL RESTAPI request data based on data from plugin.
        :return: {} if there is any error.
        """

        acl_rules_list = []
        seq = 100
        rlist = fw['firewall_rule_list']
        for r in rlist:
            if not r['enabled']:
                continue
            ace_rule = {'sequence': str(seq)}
            seq += 1

            ace_rule['protocol'] = r['protocol']

            if r['action'].lower() == 'allow':
                ace_rule['action'] = 'permit'
            elif r['action'].lower() == 'deny':
                ace_rule['action'] = 'deny'

            if 'source_ip_address' in r:
                if r['source_ip_address']:
                    ace_rule['source'] = r['source_ip_address']
                else:
                    ace_rule['source'] = 'any'
            else:
                ace_rule['source'] = 'any'

            if 'destination_ip_address' in r:
                if r['destination_ip_address']:
                    ace_rule['destination'] = r['destination_ip_address']
                else:
                    ace_rule['destination'] = 'any'
            else:
                ace_rule['destination'] = 'any'

            l4_opt = {}
            if 'source_port' in r:
                if r['source_port']:
                    src_ports = r['source_port'].split(':')
                    l4_opt['src-port-start'] = src_ports[0]
                    if len(src_ports) == 2:
                        l4_opt['src-port-end'] = src_ports[1]
            if 'destination_port' in r:
                if r['destination_port']:
                    dst_ports = r['destination_port'].split(':')
                    l4_opt['dest-port-start'] = dst_ports[0]
                    if len(dst_ports) == 2:
                        l4_opt['dest-port-end'] = dst_ports[1]
            if l4_opt:
                ace_rule['L4-options'] = l4_opt

            acl_rules_list.append(ace_rule)

        return {'rules': acl_rules_list}

    def _get_acl_id_for_fw(self, fw):
        if 'acl_id' not in fw['vendor_ext']:
            LOG.debug("ERROR: firewall [%s] has no acl_id", fw['id'])
            return ''
        return fw['vendor_ext']['acl_id']

    def _get_interface_no_from_hosting_port(self, port):
        _name = port['hosting_info']['hosting_port_name']
        if_type = _name.split(':')[0] + ':'
        if if_type == 't1_p:':
            return str(int(_name.split(':')[1]) * 2)
        else:
            return str(int(_name.split(':')[1]) * 2 + 1)

    def _get_interface_name_from_hosting_port(self, port):
        vlan = port['hosting_info']['segmentation_id']
        int_no = self._get_interface_no_from_hosting_port(port)
        intfc_name = 'GigabitEthernet%s.%s' % (int_no, vlan)
        return intfc_name

    def _post_acl_to_intfs(self, fw, csr, acl_id, status_data):
        acl_if_url = ACL_API_ACLID_IF % acl_id
        fw_if_list = fw['vendor_ext']['if_list']
        for fw_if in fw_if_list:
            if_name = self._get_interface_name_from_hosting_port(fw_if['port'])
            acl_if_req = {
                'if-id': if_name,
                'direction': fw_if['direction']
            }
            LOG.debug("CsrAcl _post_acl_to_intfs: acl_if_url %s", acl_if_url)
            csr.post_request(acl_if_url, acl_if_req)
            if csr.status == requests.codes.CREATED:
                status_data['if_list'].append({'port_id': fw_if['port']['id'],
                    'status': 'OK'})
            else:
                LOG.debug("CsrAcl _post_acl_to_intfs ERROR: status %s",
                    csr.status)
                status_data['if_list'].append({'port_id': fw_if['port']['id'],
                    'status': 'ERROR'})

    def _del_acl_on_intf(self, csr, acl_id, csr_fw_if_list):
        for fw_if in csr_fw_if_list:
            my_api = ACL_API_ACLID_IFID_DIR % (
                acl_id, fw_if['if-id'], fw_if['direction'])
            #rsp = csr.delete_request(my_api)
            csr.delete_request(my_api)
            if csr.status != requests.codes.NO_CONTENT:
                LOG.debug("CsrAcl _del_acl_on_intf ERROR: status %s",
                    csr.status)

    def _get_acl_intf(self, csr, acl_id):
        my_api = ACL_API_ACLID_IF % acl_id
        rsp = csr.get_request(my_api)
        if csr.status == requests.codes.OK:
            return rsp['items']

        LOG.debug("CsrAcl _get_acl_intf ERROR: status %s", csr.status)
        return ''

    def _post_acl(self, csr, acl_data):
        rsp = csr.post_request(ACL_API, acl_data)
        if csr.status == requests.codes.CREATED:
            return rsp[rsp.rfind('/') + 1:]

        LOG.debug("CsrAcl _post_acl ERROR: status %s", csr.status)
        return ''

    def _del_acl(self, csr, acl_id):
        my_api = ACL_API_ACLID % acl_id
        csr.delete_request(my_api)
        if csr.status == requests.codes.NO_CONTENT:
            return True

        LOG.debug("CsrAcl _del_acl ERROR: status %s", csr.status)
        return False

    def _put_acl(self, csr, acl_id, acl_data):
        my_api = ACL_API_ACLID % acl_id
        csr.put_request(my_api, acl_data)
        if csr.status == requests.codes.NO_CONTENT:
            return True

        LOG.debug("CsrAcl _put_acl ERROR: status %s", csr.status)
        return False

    def _create_fw(self, fw):
        """Create ACL and apply ACL to interfaces.

        :return: True and status_data if OK
        :return: False and status_data if there is an error
        """

        LOG.debug("CsrAcl _create_fw: fw %s", fw)
        if not self._validate_fw_data(fw):
            return False, {}
        if not self._validate_fw_rule_data(fw):
            LOG.debug("CsrAcl _create_fw: invalid rule data")
            return False, {}

        csr = self._get_csr_host(fw['vendor_ext'])
        acl_data = self._get_acl_rule_data(fw)
        LOG.debug("CsrAcl _create_fw: acl_data %s", acl_data)

        acl_id = self._post_acl(csr, acl_data)
        if not acl_id:
            LOG.debug("CsrAcl _create_fw: No acl_id created, acl_data %s",
                acl_data)
            return False, {}
        LOG.debug("CsrAcl _create_fw: new ACL ID: %s", acl_id)

        status_data = {
            'fw_id': fw['id'],
            'acl_id': acl_id,
            'if_list': []
        }

        if not fw['admin_state_up']:
            LOG.debug("CsrAcl _create_fw: status %s", status_data)
            return True, status_data

        # apply ACL to interfaces
        self._post_acl_to_intfs(fw, csr, acl_id, status_data)

        LOG.debug("CsrAcl _create_fw: status %s", status_data)
        return True, status_data

    def _delete_fw(self, fw):
        """Delete ACL.

        :return: True if OK
        :return: False if there is an error
        """

        if not self._validate_fw_data(fw):
            return False

        acl_id = self._get_acl_id_for_fw(fw)
        if not acl_id:
            LOG.debug("CsrAcl _delete_fw: firewal (%s) has no acl_id",
                fw['id'])
            return False

        csr = self._get_csr_host(fw['vendor_ext'])
        rsp = self._del_acl(csr, acl_id)
        return rsp

    def _update_fw(self, fw):
        """Update ACL and associated interfacesr.

        :return: True and status_data if OK
        :return: False and {} if there is an error
        """

        if not self._validate_fw_data(fw):
            return False, {}
        if not self._validate_fw_rule_data(fw):
            return False, {}

        acl_id = self._get_acl_id_for_fw(fw)
        if not acl_id:
            LOG.debug("CsrAcl _update_fw: firewal (%s) has no acl_id",
                fw['id'])
            return False, {}

        csr = self._get_csr_host(fw['vendor_ext'])
        rest_acl_rules = self._get_acl_rule_data(fw)
        rest_acl_rules['acl-id'] = acl_id

        # update ACL rules
        rsp = self._put_acl(csr, acl_id, rest_acl_rules)
        if not rsp:
            return False, {}

        status_data = {
            'fw_id': fw['id'],
            'acl_id': acl_id,
            'if_list': []
        }

        # update ACL interface
        # get all interfaces with this acl_id
        csr_fw_if_list = self._get_acl_intf(csr, acl_id)
        self._del_acl_on_intf(csr, acl_id, csr_fw_if_list)

        if not fw['admin_state_up']:
            return True, status_data

        self._post_acl_to_intfs(fw, csr, acl_id, status_data)
        return True, status_data

    def create_firewall(self, apply_list, firewall):
        """Create firewall on CSR."""
        LOG.debug("CsrAcl create_firewall: firewall %s", firewall)
        return self._create_fw(firewall)

    def delete_firewall(self, apply_list, firewall):
        """Delete firewall on CSR."""
        LOG.debug("CsrAcl delete_firewall: firewall %s", firewall)
        return self._delete_fw(firewall)

    def update_firewall(self, apply_list, firewall):
        """Update firewall on CSR."""
        LOG.debug("CsrAcl update_firewall: firewall %s", firewall)
        return self._update_fw(firewall)

    def apply_default_policy(self, apply_list, firewall):
        # CSR firewall driver does not support this for now
        LOG.debug("CsrAcl: apply_default_policy")
