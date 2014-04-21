__author__ = 'nalle'


from neutron.common import rpc as q_rpc
from neutron.db import api as qdbapi
from neutron.db import db_base_plugin_v2
from neutron.plugins.cisco.l3.scheduler import filter_rpc
from neutron.db import model_base
from neutron.openstack.common import rpc

class FilterSchedulerRpcCallbacks(filter_rpc.FilterSchedulerCallback):

    RPC_API_VERSION = '1.0'

    def create_rpc_dispatcher(self):

        return q_rpc.PluginRpcDispatcher([self])

class FilterSchedulerPlugin(db_base_plugin_v2.CommonDbMixin):

    def __init__(self):
        qdbapi.register_models(base=model_base.BASEV2)
        self.setup_rpc()

    def setup_rpc(self):

        self.topic = 'filter_scheduler'
        self.conn = rpc.create_connection(new=True)
        self.callbacks = FilterSchedulerRpcCallbacks()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        self.conn.consume_in_thread()