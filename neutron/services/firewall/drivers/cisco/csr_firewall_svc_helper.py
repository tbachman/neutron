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
from neutron import context as n_context
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.cfg_agent.service_helpers import service_helper
from neutron.plugins.common import constants
from neutron.services.firewall.drivers.cisco import csr_acl_driver

LOG = logging.getLogger(__name__)

CSR_FW_EV_Q_NM = 'csr_fw_ev_q'
CSR_FW_EV_CREATE = 'FW_EV_CREATE'
CSR_FW_EV_UPDATE = 'FW_EV_UPDATE'
CSR_FW_EV_DELETE = 'FW_EV_DELETE'


class CsrFirewalllPluginApi(n_rpc.RpcProxy):
    """CsrFirewallServiceHelper (Agent) side of the ACL RPC API."""

    RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        LOG.debug("CsrFirewalllPluginApi __init__")
        super(CsrFirewalllPluginApi, self).__init__(
            topic, default_version=self.RPC_API_VERSION)
        self.host = host

    def get_firewalls_for_device(self, context, **kwargs):
        """Get Firewalls with rules for a device from Plugin."""
        LOG.debug("CsrFirewalllPluginApi get_firewalls_for_device")
        return self.call(context,
                         self.make_msg('get_firewalls_for_device',
                                       host=self.host),
                         topic=self.topic)

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Get Firewalls with rules for a tenant from the Plugin."""
        LOG.debug("CsrFirewalllPluginApie get_firewalls_for_tenant")
        return self.call(context,
                         self.make_msg('get_firewalls_for_tenant',
                                       host=self.host),
                         topic=self.topic)

    def get_tenants_with_firewalls(self, context, **kwargs):
        """Get Tenants that have Firewalls configured from plugin."""
        LOG.debug("CsrFirewalllPluginApi get_tenants_with_firewalls")
        return self.call(context,
                         self.make_msg('get_tenants_with_firewalls',
                                       host=self.host),
                         topic=self.topic)

    def set_firewall_status(self, context, fw_id, status, status_data=None):
        """Make a RPC to set the status of a firewall."""
        LOG.debug("CsrFirewalllPluginApi set_firewall_status")
        return self.call(context,
                         self.make_msg('set_firewall_status', host=self.host,
                                       firewall_id=fw_id, status=status,
                                       status_data=status_data),
                         topic=self.topic)

    def firewall_deleted(self, context, firewall_id):
        """Make a RPC to indicate that the firewall resources are deleted."""
        return self.call(context,
                         self.make_msg('firewall_deleted', host=self.host,
                                       firewall_id=firewall_id),
                         topic=self.topic)


class CsrFirewallServiceHelper(service_helper.ServiceHelperBase):

    def __init__(self, host, conf, cfg_agent):
        LOG.debug("CsrFirewallServiceHelper init")
        super(CsrFirewallServiceHelper, self).__init__()
        self.conf = conf
        self.cfg_agent = cfg_agent
        self.fullsync = True
        self.ev_q = service_helper.QueueMixin()
        self.fwplugin_rpc = CsrFirewalllPluginApi(
                                        'CISCO_FW_PLUGIN', conf.host)
        self.topic = 'CISCO_FW'
        self._setup_rpc()

        self.acl_driver = csr_acl_driver.CsrAclDriver()

    def _setup_rpc(self):
        LOG.debug("CsrFW, _setup_rpc, topic %s", self.topic)
        self.conn = n_rpc.create_connection(new=True)
        self.endpoints = [self]
        self.conn.create_consumer(self.topic,
                                  self.endpoints, fanout=True)
        self.conn.consume_in_threads()

    ### Notifications from Plugin ####

    def create_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to create a firewall."""
        LOG.debug("CsrFW create_firewall: firewall %s", firewall)
        ev_data = {'ev': CSR_FW_EV_CREATE,
                   'ctx': context,
                   'fw': firewall,
                   'host': host}
        self.ev_q.enqueue(CSR_FW_EV_Q_NM, ev_data)

    def update_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to update a firewall."""
        LOG.debug("CsrFW update_firewall: firewall %s", firewall)
        ev_data = {'ev': CSR_FW_EV_UPDATE,
                   'ctx': context,
                   'fw': firewall,
                   'host': host}
        self.ev_q.enqueue(CSR_FW_EV_Q_NM, ev_data)

    def delete_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to delete a firewall."""
        LOG.debug("CsrFW delete_firewall: firewall %s", firewall)
        ev_data = {'ev': CSR_FW_EV_DELETE,
                   'ctx': context,
                   'fw': firewall,
                   'host': host}
        self.ev_q.enqueue(CSR_FW_EV_Q_NM, ev_data)

    def _invoke_fw_driver(self, context, fw, func_nm):
        LOG.debug("CsrFW _invoke_fw_driver: %s", func_nm)
        try:
            if func_nm == 'delete_firewall':
                rc = self.acl_driver.__getattribute__(func_nm)(None, fw)
                if not rc:
                    LOG.debug("CsrFW _invoke_fw_driver error: fw %s",
                        fw['id'])
                    self.fwplugin_rpc.set_firewall_status(context,
                                                      fw['id'],
                                                      constants.ERROR)
                else:
                    self.fwplugin_rpc.firewall_deleted(context, fw['id'])
            else:
                rc, status = self.acl_driver.__getattribute__(func_nm)(
                    None, fw)
                if not rc:
                    LOG.debug("CsrFW _invoke_fw_driver error: fw %s", fw['id'])
                    self.fwplugin_rpc.set_firewall_status(context,
                                                      fw['id'],
                                                      constants.ERROR)
                else:
                    LOG.debug("Csr FW _invoke_fw_driver, status %s", status)
                    self.fwplugin_rpc.set_firewall_status(context,
                                                          fw['id'],
                                                          constants.ACTIVE,
                                                          status)
        except Exception:
            LOG.debug("CsrFW _invoke_fw_driver: PRC failure")
            self.fullsync = True

    def _process_fw_pending_op(self, context, fw_list):
        for fw in fw_list:
            fw_status = fw['status']
            if fw_status == 'PENDING_CREATE':
                self._invoke_fw_driver(context, fw, 'create_firewall')
            elif fw_status == 'PENDING_UPDATE':
                self._invoke_fw_driver(context, fw, 'update_firewall')
            elif fw_status == 'PENDING_DELETE':
                self._invoke_fw_driver(context, fw, 'delete_firewall')

    def _process_fullsync(self):
        try:
            context = n_context.get_admin_context()
            tenants = self.fwplugin_rpc.get_tenants_with_firewalls(context)
            LOG.debug("CsrFW _process_fullsync: tenants with fw: %s",
                tenants)
            for tenant_id in tenants:
                ctx = n_context.Context('', tenant_id)
                fw_list = self.fwplugin_rpc.get_firewalls_for_tenant(ctx)
                self._process_fw_pending_op(ctx, fw_list)

        except Exception:
            LOG.debug("CsrFW _process_fullsync: RPC failure")
            self.fullsync = True

    def _process_devices(self, device_ids):
        LOG.debug("CsrFW _process_devices: device_ids %s", device_ids)
        try:
            for dvc_id in device_ids:
                ctx = n_context.Context('', dvc_id)
                fw_list = self.fwplugin_rpc.get_firewalls_for_device(ctx)
                self._process_fw_pending_op(ctx, fw_list)

        except Exception:
            LOG.debug("CsrFW _process_devices: RPC failure")
            self.fullsync = True

    def _process_event_q(self):
        LOG.debug("CsrFW _process_event_q:")
        while True:
            try:
                ev_data = self.ev_q.dequeue(CSR_FW_EV_Q_NM)
                if not ev_data:
                    LOG.debug("CsrFW _process_event_q: no evt in q")
                    return
            except ValueError:
                LOG.debug("CsrFW _process_event_q: no queue yet")
                return

            LOG.debug("CsrFW _process_event_q: ev_data %s", ev_data)
            ev = ev_data['ev']
            ctx = ev_data['ctx']
            fw = ev_data['fw']
            if ev == CSR_FW_EV_CREATE:
                self._invoke_fw_driver(ctx, fw, 'create_firewall')
            elif ev == CSR_FW_EV_UPDATE:
                self._invoke_fw_driver(ctx, fw, 'update_firewall')
            elif ev == CSR_FW_EV_DELETE:
                self._invoke_fw_driver(ctx, fw, 'delete_firewall')
            else:
                LOG.debug("CsrFW _process_event_q: invalid ev %s", ev)

    def process_service(self, device_ids=None, removed_devices_info=None):
        LOG.debug("CsrFW process_service:")
        try:
            if self.fullsync:
                LOG.debug("CsrFW process_service: fullsync")
                self.fullsync = False
                self._process_fullsync()

            else:
                if device_ids:
                    LOG.debug("CsrFW process_service: device_ids %s",
                        device_ids)
                    self._process_devices(device_ids)

                if removed_devices_info:
                    LOG.debug("CsrFW process_service: removed_dvc_info %s",
                        removed_devices_info)
                    # do nothing for now
                else:
                    LOG.debug("CsrFW process_service: normal")
                    self._process_event_q()

        except Exception:
            LOG.exception(_('CsrFW process_service exception ERROR'))
