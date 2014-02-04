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

import six


@six.add_metaclass(abc.ABCMeta)
class VpnDriver(object):

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


class GenericVPNRpcDriver(VpnDriver):

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
        so we need handle their resources.
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
