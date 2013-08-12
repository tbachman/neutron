# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

from neutron.common import rpc as n_rpc
from neutron.extensions import vpnaas
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.openstack.common.rpc import proxy
from neutron.plugins.common import utils

LOG = logging.getLogger(__name__)


class GenericVPNRpcCallback(object):
    """Callback for GenricVPNDriver rpc."""
    RPC_API_VERSION = '1.0'

    def __init__(self, driver):
        self.driver = driver

    def create_rpc_dispatcher(self):
        return n_rpc.PluginRpcDispatcher([self])

    def get_vpnservices(self, context, filter=None):
        plugin = self.driver.plugin
        return plugin.get_vpnservices(context, filter=filter)

    def update_status(self, context, status):
        """Update status of vpnservices."""
        plugin = self.driver.plugin
        with context.session.begin(subtransactions=True):
            for vpnservice in status:
                try:
                    vpnservice_db = plugin._get_vpn_service(
                        context, vpnservice['id'])
                except vpnaas.VPNServiceNotFound:
                    LOG.warn(_('vpnservice is already deleted: %s'),
                             vpnservice['id'])
                    continue
                if (not utils.in_pending_status(vpnservice_db.status)
                    or vpnservice['updated_pending_status']):
                    vpnservice_db.status = vpnservice['status']


class VPNDriver(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, plugin):
        self.plugin = plugin

    @property
    def service_type(self):
        pass

    @abc.abstractmethod
    def create_vpnservice(self, context, vpnservice):
        pass

    @abc.abstractmethod
    def update_vpnservice(
        self, context, old_vpnservice, vpnservice):
        pass

    @abc.abstractmethod
    def delete_vpnservice(self, context, vpnservice):
        pass


class GenericVPNRpcDriver(VPNDriver):

    def __init__(self, plugin):
        super(GenericVPNRpcDriver, self).__init__(plugin)
        self.callbacks = GenericVPNRpcCallback(self)
        self.agent_rpc = proxy.RpcProxy('generic_vpn_rpc', '1.0')
        self.conn = rpc.create_connection(new=True)
        self.conn.create_consumer(
            'vpn_rpc',
            self.callbacks.create_rpc_dispatcher(),
            fanout=False)
        self.conn.consume_in_thread()

    def create_vpnservice(self, context, vpnservice):
        self.agent_rpc.cast(
            context,
            self.agent_rpc.make_msg('create_vpnservice',
                                    resource=vpnservice),
            topic="vpn_rpc_%s" % vpnservice['provider']
        )

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        self.agent_rpc.cast(
            context,
            self.agent_rpc.make_msg('update_vpnservice',
                                    old_resource=old_vpnservice,
                                    resource=vpnservice),
            topic="vpn_rpc_%s" % vpnservice['provider']
        )

    def delete_vpnservice(self, context, vpnservice):
        self.agent_rpc.cast(
            context,
            self.agent_rpc.make_msg('delete_vpnservice',
                                    resource=vpnservice),
            topic="vpn_rpc_%s" % vpnservice['provider']
        )

    def __getattr__(self, key):
        """Handling create/update/delete method call.

        Vpnaas service may extend actions,
        so we need handle thier resources.
        """
        def rpc_cast(context, *args):
            """Rpc for Resource Event call.

            This rpc call function notifies
            event for specified resource.
            """
            kwargs = {}
            if len(args) == 2:
                kwargs['old_resource'] = args[0]
                kwargs['resource'] = args[1]
            elif len(args) == 1:
                kwargs['resource'] = args[0]
            else:
                #This method signature is undefined
                raise AttributeError()

            vpnservice_id = kwargs['resource'].get('vpnservice_id')
            if not vpnservice_id:
                #GenricVPNDriver defines only function which has
                #a resource with vpnservice_id
                raise AttributeError()
            vpnservice = self.plugin._get_vpnservice(
                context, vpnservice_id)
            topic = "vpn_rpc_%s" % vpnservice['provider']
            self.agent_rpc.cast(
                context,
                self.agent_rpc.make_msg(key, **kwargs),
                topic=topic)
        return rpc_cast
