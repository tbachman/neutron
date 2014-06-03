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
#
# @author: Hareesh Puthalath, Cisco Systems, Inc.

import eventlet
import sys
import time

from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent import rpc as agent_rpc
from neutron.common import topics
from neutron import context as n_context
from neutron import manager
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import periodic_task
from neutron.openstack.common.rpc import proxy
from neutron.openstack.common import service
from neutron.plugins.cisco.cfg_agent.device_status import DeviceStatus
from neutron.plugins.cisco.common import cisco_constants as c_constants
from neutron.plugins.cisco.cfg_agent.service_helpers.routing_svc_helper import(
    RoutingServiceHelper)
from neutron import service as neutron_service

LOG = logging.getLogger(__name__)

# Constants for agent registration.
REGISTRATION_RETRY_DELAY = 2
MAX_REGISTRATION_ATTEMPTS = 20


class CiscoDeviceManagerPluginApi(proxy.RpcProxy):
    """Agent side of the device manager RPC API."""

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(CiscoDeviceManagerPluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def report_dead_hosting_devices(self, context, hd_ids=[]):
        """Report that a hosting device cannot be contacted (presumed dead).

        :param: context: session context
        :param: hosting_device_ids: list of non-responding hosting devices
        :return: None
        """
        # Cast since we don't expect a return value.
        self.cast(context,
                  self.make_msg('report_non_responding_hosting_devices',
                                host=self.host,
                                hosting_device_ids=hd_ids),
                  topic=self.topic)

    def register_for_duty(self, context):
        """Report that a config agent is ready for duty.
        """
        # Cast since we don't expect a return value.
        return self.call(context, self.make_msg('register_for_duty',
                                                host=self.host),
                         topic=self.topic)


class CiscoCfgAgent(manager.Manager):
    """Cisco Cfg Agent.

    This class defines a generic configuration agent for cisco devices which
    implement network services in the cloud backend. It is based on the
    (reference) l3-agent, and tries to preserve code where possible.

    The agent by itself does not do any configuration. All device specific
    configurations are done by hosting device drivers which implement the
    service api, (defined in service_api.py) for various services (eg: Routing)

    The main entry points in this class are the `_sync_task()` and
    `_rpc_loop()` .
    """
    RPC_API_VERSION = '1.1'

    OPTS = [
        cfg.IntOpt('rpc_loop_interval', default=10,
                   help=_("Interval when the rpc loop executes. This is when "
                          "agent fetches info about the updated or removed "
                          "routers notified from a plugin side RPC.")),
    ]

    def __init__(self, host, conf=None):
        self.conf = conf or cfg.CONF
        self._dev_status = DeviceStatus()
        self.context = n_context.get_admin_context_without_session()

        self._initialize_rpc(host)
        self._initialize_service_helpers(host)
        self._start_periodic_tasks()
        super(CiscoCfgAgent, self).__init__(host=self.conf.host)

    def _initialize_rpc(self, host):
        self.devmgr_rpc = CiscoDeviceManagerPluginApi(
            topics.DEVICE_MANAGER_PLUGIN, host)

    def _initialize_service_helpers(self, host):
        self.routing_service_helper = RoutingServiceHelper(host, self.conf,
                                                           self)

    def _start_periodic_tasks(self):
        self.rpc_loop = loopingcall.FixedIntervalLoopingCall(self._rpc_loop)
        self.rpc_loop.start(interval=self.conf.rpc_loop_interval)

    def after_start(self):
        LOG.info(_("Cisco cfg agent started"))

    def get_routing_service_helper(self):
        return self.routing_service_helper

    ## Periodic tasks ##

    @lockutils.synchronized('cisco-cfg-agent', 'neutron-')
    def _rpc_loop(self):
        """Process routers received via RPC.

        This method  executes every `RPC_LOOP_INTERVAL` seconds and processes
        routers which have been notified via RPC from the plugin. Plugin sends
        RPC messages for updated or removed routers, whose router_ids are kept
        in `updated_routers` and `removed_routers` respectively. For router in
        `updated_routers` we fetch the latest state for these routers from
        the plugin and process them. Routers in `removed_routers` are
        removed from the hosting device and from the set of routers which the
        agent is tracking (router_info attribute).

        Note that this will not be executed at the same time as the
        `_sync_task()` because of the lock which avoids race conditions
         on `updated_routers` and `removed_routers`

        :return: None
        """
        LOG.debug(_("Starting RPC loop for processing services"))
        self.process_services()
        LOG.debug(_("RPC loop successfully completed"))

    @periodic_task.periodic_task
    @lockutils.synchronized('cisco-cfg-agent', 'neutron-')
    def _backlog_task(self, context):
        """Process backlogged devices
        """
        LOG.debug(_("Processing backlog."))
        #ToDo(Hareesh): Verify backlog processing
        self._process_backlogged_hosting_devices(context)

    ## Main orchestrator ##
    def process_services(self):
        """Process services associated with a hosting device.

        This method dictates the order of processing of services.
        Any cross dependencies should be solved here, thus making it a
        single point of change for interaction among services.

        :param resources: dict of resources. Valid keys now are 'routers',
        'removed_routers' and 'all_routers'(flag)
        :return: None
        """
        #ToDo(Hareesh): Verify admin_up event
        LOG.debug(_("Processing services started"))
        # First we process routing service
        self.routing_service_helper.process_service()
        LOG.debug(_("Processing services completed"))

    def process_services_for_devices(self, devices):
        """Process services on a list of hosting devices.

        This method dictates the order of processing of services.
        Any cross dependencies should be solved here, thus making it a
        single point of change for interaction among services.

        :param devices: List of hosting devices
        :return: None
        """
        LOG.debug(_("Processing services started"))
        self.routing_service_helper.process_service_for_devices(devices)
        LOG.debug(_("Processing services completed"))

    def _process_backlogged_hosting_devices(self, context):
        """Process currently back logged devices.

        Go through the currently backlogged devices and process them.
        For devices which are now reachable (compared to last time), we fetch
        the routers they are hosting and process them.
        For devices which have passed the `hosting_device_dead_timeout` and
        hence presumed dead, execute a RPC to the plugin informing that.
        :param context: RPC context
        :return: None
        """
        res = self._dev_status.check_backlogged_hosting_devices()
        if res['reachable']:
            self.process_services_for_devices(res['reachable'])
        if res['dead']:
            LOG.debug(_("Reporting dead hosting devices: %s"),
                      res['dead'])
            self.devmgr_rpc.report_dead_hosting_devices(context,
                                                        hd_ids=res['dead'])


class CiscoCfgAgentWithStateReport(CiscoCfgAgent):

    def __init__(self, host, conf=None):
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'neutron-cisco-cfg-agent',
            'host': host,
            'topic': c_constants.CFG_AGENT,
            'configurations': {},
            'start_flag': True,
            'agent_type': c_constants.AGENT_TYPE_CFG}
        report_interval = cfg.CONF.AGENT.report_interval
        self.use_call = True
        self._initialize_rpc(host)
        self._agent_registration()
        super(CiscoCfgAgentWithStateReport, self).__init__(host=host,
                                                           conf=conf)
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _agent_registration(self):
        for attempts in xrange(MAX_REGISTRATION_ATTEMPTS):
            context = n_context.get_admin_context_without_session()
            self.send_agent_report(self.agent_state, context)
            res = self.devmgr_rpc.register_for_duty(context)
            if res is True:
                LOG.info(_("[Agent registration] Agent successfully "
                           "registered"))
                return
            elif res is False:
                LOG.warn(_("[Agent registration] Neutron server said that "
                           "device manager was not ready. Retrying in %0.2f "
                           "seconds "), REGISTRATION_RETRY_DELAY)
                time.sleep(REGISTRATION_RETRY_DELAY)
            elif res is None:
                LOG.error(_("[Agent registration] Neutron server said that no "
                            "device manager was found. Exiting!"))
                sys.exit(1)
        LOG.error(_("[Agent registration] %d unsuccessful registration "
                    "attempts. Exiting!"), MAX_REGISTRATION_ATTEMPTS)
        sys.exit(1)

    def _report_state(self):
        """Report state back to the plugin.

        This is run every `report_interval` period. This attribute is part
        of the agent's configuration.
        Collects, creates and sends a RPC notification with a summary of
        logical routers, hosting devices and other attributes which together
        represent a snapshot of what this agent is managing.
        Look at the `configurations` dict for the parameters reported.
        :return: None
        """
        LOG.debug(_("Report state task started"))
        configurations = self.agent_state['configurations']
        self.routing_service_helper.collect_state(configurations)
        self.send_agent_report(self.agent_state, self.context)

    def send_agent_report(self, report, context):
        try:
            self.state_rpc.report_state(context, report, self.use_call)
            report.pop('start_flag', None)
            self.use_call = False
            LOG.debug(_("Send agent report successfully completed"))
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_("Neutron server does not support state report. "
                       "State report for this agent will be disabled."))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_("Failed sending agent report!"))

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event.

        Plugin sets the `admin_status_up` flag. If `admin-status-up` is set,
        we set full_sync, which will cause a full refresh for routers
        belonging to this agent.
        Payload format : {'admin_state_up': admin_state_up}
        """
        #ToDo(Hareesh): Check if this is needed else remove
        raise NotImplementedError


def main(manager='neutron.plugins.cisco.cfg_agent.'
                 'cfg_agent.CiscoCfgAgentWithStateReport'):
    eventlet.monkey_patch()
    conf = cfg.CONF
    conf.register_opts(CiscoCfgAgent.OPTS)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    conf(project='neutron')
    config.setup_logging(conf)
    server = neutron_service.Service.create(
        binary='neutron-cisco-cfg-agent',
        topic=c_constants.CFG_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager=manager)
    service.launch(server).wait()
