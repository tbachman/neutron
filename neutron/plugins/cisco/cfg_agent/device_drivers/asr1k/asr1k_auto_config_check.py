import sys

import ciscoconfparse
import ncclient

import oslo_messaging
from oslo_config import cfg

from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import config as common_config
from neutron import context as ctxt

class CiscoDevMgrRPC(object):
    """Agent side of the device manager RPC API."""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_all_hosting_devices(self, context):
        """Get a list of all hosting devices."""
        cctxt = self.client.prepare()
        return cctxt.call(context,
                          'get_all_hosting_devices',
                          host=self.host)

class CiscoRoutingPluginRPC(object):
    """RoutingServiceHelper(Agent) side of the  routing RPC API."""

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_routers(self, context, router_ids=None, hd_ids=None):
        """Make a remote process call to retrieve the sync data for routers.

        :param context: session context
        :param router_ids: list of  routers to fetch
        :param hd_ids : hosting device ids, only routers assigned to these
                        hosting devices will be returned.
        """
        cctxt = self.client.prepare()
        return cctxt.call(context, 'cfg_sync_routers', host=self.host,
                          router_ids=router_ids, hosting_device_ids=hd_ids)

def main():

    conf = cfg.CONF

    common_config.init(sys.argv[1:])
    conf(project='neutron')

    host = conf.host
    devmgr_rpc = CiscoDevMgrRPC(topics.DEVICE_MANAGER_PLUGIN, host)
    plugin_rpc = CiscoRoutingPluginRPC(topics.L3PLUGIN, host)

    context = ctxt.Context('','')
    # TODO: create an admin context instead
    hosting_devs = devmgr_rpc.get_all_hosting_devices(context)
    for hd in hosting_devs['hosting_devices']:
        print("HOSTING DEVICE: %s" % hd)

if __name__ == "__main__":
    main()
