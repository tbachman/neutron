# Copyright 2013 OpenStack Foundation
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

"""
ML2 Mechanism Driver for Cisco Nexus platforms.
"""

import os
import threading

from oslo.config import cfg

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.openstack.common import excutils
from neutron.openstack.common.gettextutils import _LW, _LI
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.nexus import config as conf
from neutron.plugins.ml2.drivers.cisco.nexus import constants as const
from neutron.plugins.ml2.drivers.cisco.nexus import credentials_v2 as cred
from neutron.plugins.ml2.drivers.cisco.nexus import exceptions as excep
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_db_v2 as nxos_db
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_network_driver

LOG = logging.getLogger(__name__)


class CiscoNexusCfgMonitor(object):
    """Replay config on communication failure between Openstack to Nexus."""

    def __init__(self, driver, mdriver):
        self._driver = driver
        self._mdriver = mdriver
        switch_connections = self._mdriver.get_switch_ips()
        for switch_ip in switch_connections:
            self._mdriver.set_switch_ip_and_active_state(
                switch_ip, False)

    def _configure_nexus_type(self, switch_ip, nexus_type):
        if nexus_type not in (const.NEXUS_3K, const.NEXUS_5K,
                              const.NEXUS_7K, const.NEXUS_9K):
            LOG.error(_("Received invalid Nexus type %(nexus_type)d for switch"
                      "for switch ip %(switch_ip)s"),
                      {'nexus_type': nexus_type, 'switch_ip': switch_ip})
            return
        if (self._mdriver.get_switch_nexus_type(switch_ip) ==
           const.NEXUS_TYPE_INVALID):
            self._mdriver.set_switch_nexus_type(switch_ip, nexus_type)

    def replay_config(self, switch_ip):
        """Sends pending config data in OpenStack to Nexus."""
        LOG.debug(_("Replaying config for switch ip %(switch_ip)s"),
                  {'switch_ip': switch_ip})

        try:
            port_bindings = nxos_db.get_nexusport_switch_bindings(switch_ip)
        except excep.NexusPortBindingNotFound:
            LOG.debug(_("No port entries found for switch ip "
                      "%(switch_ip)s during replay."),
                      {'switch_ip': switch_ip})
            return

        self._mdriver.configure_switch_entries(switch_ip,
                                               port_bindings)

    def check_connections(self):
        """Check connection between Openstack to Nexus device."""
        switch_connections = self._mdriver.get_switch_state()

        for switch_ip in switch_connections:
            state = self._mdriver.get_switch_ip_and_active_state(switch_ip)
            retry_count = self._mdriver.get_switch_retry_count(switch_ip)
            cfg_retry = conf.cfg.CONF.ml2_cisco.switch_replay_count
            if retry_count > cfg_retry:
                continue
            if retry_count == cfg_retry:
                LOG.debug(_("check_connections() switch "
                          "%(switch_ip)s retry count %(rcnt)d exceeded "
                          "configured threshold %(thld)d"),
                          {'switch_ip': switch_ip, 'state': state,
                           'rcnt': retry_count,
                           'thld': cfg_retry})
                self._mdriver.incr_switch_retry_count(switch_ip)
                continue
            LOG.debug(_("check_connections() switch "
                      "%(switch_ip)s state %(state)d"),
                      {'switch_ip': switch_ip, 'state': state})
            try:
                nexus_type = self._driver.get_nexus_type(switch_ip)
            except Exception:
                if state is True:
                    LOG.error(_("Lost connection to switch ip %(switch_ip)s"),
                              {'switch_ip': switch_ip})
                    self._mdriver.set_switch_ip_and_active_state(
                        switch_ip, False)
            else:
                if state is False:
                    self._configure_nexus_type(switch_ip, nexus_type)
                    LOG.debug(_("Re-established connection to switch "
                              "ip %(switch_ip)s"),
                              {'switch_ip': switch_ip})
                    self._mdriver.set_switch_ip_and_active_state(
                        switch_ip, True)
                    self.replay_config(switch_ip)
                    # If replay failed, it stops trying to configure db entries
                    # and sets switch state to False so this caller knows
                    # it failed.  If it did fail, we increment the
                    # retry counter else reset it to 0.
                    if self._mdriver.get_switch_ip_and_active_state(
                        switch_ip) is False:
                        self._mdriver.incr_switch_retry_count(switch_ip)
                        LOG.warn(_LW("Replay config failed for "
                                 "ip %(switch_ip)s"),
                                 {'switch_ip': switch_ip})
                    else:
                        self._mdriver.reset_switch_retry_count(switch_ip)
                        LOG.info(_LI("Replay config successful for "
                                 "ip %(switch_ip)s"),
                                 {'switch_ip': switch_ip})


class CiscoNexusMechanismDriver(api.MechanismDriver):

    """Cisco Nexus ML2 Mechanism Driver."""

    def initialize(self):
        # Create ML2 device dictionary from ml2_conf.ini entries.
        conf.ML2MechCiscoConfig()

        # Extract configuration parameters from the configuration file.
        self._nexus_switches = conf.ML2MechCiscoConfig.nexus_dict
        LOG.debug(_("nexus_switches found = %s"), self._nexus_switches)
        # Save dynamic switch information
        self._switch_state = {}

        self.credentials = {}
        self.driver = nexus_network_driver.CiscoNexusDriver()

        # Initialize credential store after database initialization.
        cred.Store.initialize()

        # This method is only called once regardless of number of
        # api/rpc workers defined.
        self._ppid = os.getpid()

        self.monitor = CiscoNexusCfgMonitor(self.driver, self)
        self.timer = None
        self.monitor_timeout = conf.cfg.CONF.ml2_cisco.switch_heartbeat_time
        self.monitor_lock = threading.Lock()
        # Start the monitor thread
        if self.monitor_timeout > 0:
            self._monitor_thread()

    def set_switch_ip_and_active_state(self, switch_ip, state):
        self._switch_state[switch_ip, '_connect_active'] = state

    def get_switch_ip_and_active_state(self, switch_ip):
        if (switch_ip, '_connect_active') in self._switch_state:
            return self._switch_state[switch_ip, '_connect_active']
        else:
            return False

    def register_switch_as_inactive(self, switch_ip, func_name):
        self.set_switch_ip_and_active_state(switch_ip, False)
        LOG.exception(
            _("Nexus Driver cisco_nexus failed in %(func_name)s"),
            {'func_name': func_name})

    def set_switch_nexus_type(self, switch_ip, type):
        self._switch_state[switch_ip, '_nexus_type'] = type

    def get_switch_nexus_type(self, switch_ip):
        if (switch_ip, '_nexus_type') in self._switch_state:
            return self._switch_state[switch_ip, '_nexus_type']
        else:
            return -1

    def reset_switch_retry_count(self, switch_ip):
        self._switch_state[switch_ip, '_retry_count'] = 0

    def incr_switch_retry_count(self, switch_ip):
        if (switch_ip, '_retry_count') in self._switch_state:
            self._switch_state[switch_ip, '_retry_count'] += 1
        else:
            self.reset_switch_retry_count(switch_ip)

    def get_switch_retry_count(self, switch_ip):
        if (switch_ip, '_retry_count') not in self._switch_state:
            self.reset_switch_retry_count(switch_ip)
        return self._switch_state[switch_ip, '_retry_count']

    def get_switch_state(self):
        switch_connections = []
        for switch_ip, attr in self._switch_state:
            if str(attr) == '_connect_active':
                switch_connections.append(switch_ip)

        return switch_connections

    def is_switch_configurable(self, switch_ip):
        if self.monitor_timeout > 0 and self._ppid == os.getpid():
            return self.get_switch_ip_and_active_state(switch_ip)
        else:
            return True

    def choose_to_reraise_driver_exception(self, switch_ip, func_name):

        if self.monitor_timeout > 0:
            self.register_switch_as_inactive(switch_ip, func_name)
            return False
        else:
            return True

    def _valid_network_segment(self, segment):
        return (cfg.CONF.ml2_cisco.managed_physical_network is None or
                cfg.CONF.ml2_cisco.managed_physical_network ==
                segment[api.PHYSICAL_NETWORK])

    def _get_vlanid(self, segment):
        if (segment and segment[api.NETWORK_TYPE] == p_const.TYPE_VLAN and
            self._valid_network_segment(segment)):
            return segment.get(api.SEGMENTATION_ID)

    def _is_deviceowner_compute(self, port):
        return port['device_owner'].startswith('compute')

    def _is_status_active(self, port):
        return port['status'] == n_const.PORT_STATUS_ACTIVE

    def _get_switch_info(self, host_id):
        host_connections = []
        for switch_ip, attr in self._nexus_switches:
            if str(attr) == str(host_id):
                for port_id in (
                    self._nexus_switches[switch_ip, attr].split(',')):
                    if ':' in port_id:
                        intf_type, port = port_id.split(':')
                    else:
                        intf_type, port = 'ethernet', port_id
                    host_connections.append((switch_ip, intf_type, port))

        if host_connections:
            return host_connections
        else:
            raise excep.NexusComputeHostNotConfigured(host=host_id)

    def get_switch_ips(self):
        switch_connections = []
        for switch_ip, attr in self._nexus_switches:
            if str(attr) == 'username':
                switch_connections.append(switch_ip)

        return switch_connections

    def _configure_nxos_db(self, vlan_id, device_id, host_id):
        """Create the nexus database entry.

        Called during update precommit port event.
        """
        host_connections = self._get_switch_info(host_id)
        for switch_ip, intf_type, nexus_port in host_connections:
            port_id = '%s:%s' % (intf_type, nexus_port)
            nxos_db.add_nexusport_binding(port_id, str(vlan_id),
                                          switch_ip, device_id)

    def _configure_port_binding(self, duplicate_type, switch_ip,
                                vlan_id, intf_type, nexus_port):
        """Conditionally calls vlan and port Nexus drivers."""

        # This implies VLAN, VNI, and Port are all duplicate.
        # Then there is nothing to configure in Nexus.
        if duplicate_type == const.DUPLICATE_PORT:
            return

        auto_create = True
        auto_trunk = True
        vlan_name = cfg.CONF.ml2_cisco.vlan_name_prefix + str(vlan_id)

        # if type DUPLICATE_VLAN, don't create vlan
        if duplicate_type == const.DUPLICATE_VLAN:
            auto_create = False

        if auto_create and auto_trunk:
            LOG.debug("Nexus: create & trunk vlan %s"), vlan_name
            self.driver.create_and_trunk_vlan(
                switch_ip, vlan_id, vlan_name, intf_type, nexus_port)
        elif auto_create:
            LOG.debug("Nexus: create vlan %s"), vlan_name
            self.driver.create_vlan(switch_ip, vlan_id, vlan_name)
        elif auto_trunk:
            LOG.debug("Nexus: trunk vlan %s"), vlan_name
            self.driver.enable_vlan_on_trunk_int(switch_ip, vlan_id,
                                                 intf_type, nexus_port)

    def _configure_host_entries(self, vlan_id, device_id, host_id):
        """Create a nexus switch entry.

        if needed, create a VLAN in the appropriate switch or port and
        configure the appropriate interfaces for this VLAN.

        Called during update postcommit port event.
        """
        host_connections = self._get_switch_info(host_id)

        vlan_already_created = []
        for switch_ip, intf_type, nexus_port in host_connections:

            if self.is_switch_configurable(switch_ip) is False:
                self.reset_switch_retry_count(switch_ip)
                continue

            # The VLAN needs to be created on the switch if no other
            # instance has been placed in this VLAN on a different host
            # attached to this switch.  Search the existing bindings in the
            # database.  If all the instance_id in the database match the
            # current device_id, then create the VLAN, but only once per
            # switch_ip.  Otherwise, just trunk.
            all_bindings = nxos_db.get_nexusvlan_binding(vlan_id, switch_ip)
            previous_bindings = [row for row in all_bindings
                                 if row.instance_id != device_id]
            duplicate_port = [row for row in all_bindings
                              if row.instance_id != device_id and
                              row.port_id == intf_type + ':' + nexus_port]
            if duplicate_port:
                duplicate_type = const.DUPLICATE_PORT
            elif previous_bindings or (switch_ip in vlan_already_created):
                duplicate_type = const.DUPLICATE_VLAN
            else:
                vlan_already_created.append(switch_ip)
                duplicate_type = const.NO_DUPLICATE
            try:
                self._configure_port_binding(
                    duplicate_type, switch_ip, vlan_id,
                    intf_type, nexus_port)
            except Exception:
                with excutils.save_and_reraise_exception() as ctxt:
                    ctxt.reraise = self.choose_to_reraise_driver_exception(
                        switch_ip, '_configure_port_binding')

    def configure_switch_entries(self, switch_ip, port_bindings):
        """Create a nexus switch entry in Nexus.

        The port_bindings is sorted by vlan_id, port_id.
        When there is a change in vlan_id then vlan
        data is configured in Nexus device.
        Otherwise we check if there is a change in port_id
        where we configure the port with vlan trunk config.

        Called during switch replay event.
        """
        prev_vlan = -1
        prev_port = None
        port_bindings.sort(key=lambda x: (x.vlan_id, x.port_id))
        for port in port_bindings:
            if ':' in port.port_id:
                intf_type, nexus_port = port.port_id.split(':')
            else:
                intf_type, nexus_port = 'ethernet', port.port_id
            if port.vlan_id == prev_vlan:
                duplicate_type = const.DUPLICATE_VLAN
                if port.port_id == prev_port:
                    duplicate_type = const.DUPLICATE_PORT
            else:
                duplicate_type = const.NO_DUPLICATE
            try:
                self._configure_port_binding(
                    duplicate_type,
                    switch_ip, port.vlan_id,
                    intf_type, nexus_port)
            except Exception as e:
                self.choose_to_reraise_driver_exception(
                    switch_ip, 'replay _configure_port_binding')
                LOG.debug(_("Failed to configure port binding "
                          "for switch %(switch_ip)s, vlan %(vlan)s "
                          "port %(port)s, "
                          "reason %(reason)s"),
                          {'switch_ip': switch_ip,
                           'vlan': port.vlan_id,
                           'port': port.port_id,
                           'reason': e})
                break
            prev_vlan = port.vlan_id
            prev_port = port.port_id

    def _delete_nxos_db(self, vlan_id, device_id, host_id):
        """Delete the nexus database entry.

        Called during delete precommit port event.
        """
        try:
            rows = nxos_db.get_nexusvm_bindings(vlan_id, device_id)
            for row in rows:
                nxos_db.remove_nexusport_binding(
                    row.port_id, row.vlan_id, row.switch_ip, row.instance_id)
        except excep.NexusPortBindingNotFound:
            return

    def _delete_switch_entry(self, vlan_id, device_id, host_id):
        """Delete the nexus switch entry.

        By accessing the current db entries determine if switch
        configuration can be removed.

        Called during update postcommit port event.
        """
        host_connections = self._get_switch_info(host_id)
        vlan_already_removed = []
        for switch_ip, intf_type, nexus_port in host_connections:

            if self.is_switch_configurable(switch_ip) is False:
                self.reset_switch_retry_count(switch_ip)
                continue

            # if there are no remaining db entries using this vlan on this
            # nexus switch port then remove vlan from the switchport trunk.
            port_id = '%s:%s' % (intf_type, nexus_port)
            auto_create = True
            auto_trunk = True
            try:
                nxos_db.get_port_vlan_switch_binding(port_id, vlan_id,
                                                     switch_ip)
            except excep.NexusPortBindingNotFound:
                pass
            else:
                continue

            if auto_trunk:
                try:
                    self.driver.disable_vlan_on_trunk_int(
                        switch_ip, vlan_id, intf_type, nexus_port)
                except Exception:
                    with excutils.save_and_reraise_exception() as ctxt:
                        ctxt.reraise = (
                            self.choose_to_reraise_driver_exception(
                                switch_ip,
                                'disable_vlan_on_trunk_int'))
                    continue

            # if there are no remaining db entries using this vlan on this
            # nexus switch then remove the vlan.
            if auto_create:
                try:
                    nxos_db.get_nexusvlan_binding(vlan_id, switch_ip)
                except excep.NexusPortBindingNotFound:
                    # Do not perform a second time on same switch
                    if switch_ip not in vlan_already_removed:
                        try:
                            self.driver.delete_vlan(switch_ip, vlan_id)
                        except Exception:
                            with excutils.save_and_reraise_exception() as ctxt:
                                ctxt.reraise = (
                                    self.choose_to_reraise_driver_exception(
                                        switch_ip, 'delete_vlan'))
                        vlan_already_removed.append(switch_ip)

    def _is_vm_migration(self, context):
        if not context.bound_segment and context.original_bound_segment:
            return (context.current.get(portbindings.HOST_ID) !=
                    context.original.get(portbindings.HOST_ID))

    def _port_action(self, port, segment, func):
        """Verify configuration and then process event."""
        device_id = port.get('device_id')
        host_id = port.get(portbindings.HOST_ID)
        vlan_id = self._get_vlanid(segment)

        if vlan_id and device_id and host_id:
            func(vlan_id, device_id, host_id)
        else:
            fields = "vlan_id " if not vlan_id else ""
            fields += "device_id " if not device_id else ""
            fields += "host_id" if not host_id else ""
            raise excep.NexusMissingRequiredFields(fields=fields)

    def _monitor_thread(self):
        """Periodically restarts the monitor thread."""
        with self.monitor_lock:
            self.monitor.check_connections()

        self.timer = threading.Timer(self.monitor_timeout,
                                     self._monitor_thread)
        self.timer.start()

    def _stop_monitor_thread(self):
        """Terminates the monitor thread."""
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def update_port_precommit(self, context):
        """Update port pre-database transaction commit event."""

        # if VM migration is occurring then remove previous database entry
        # else process update event.
        if self._is_vm_migration(context):
            self._port_action(context.original,
                              context.original_bound_segment,
                              self._delete_nxos_db)
        else:
            if (self._is_deviceowner_compute(context.current) and
                self._is_status_active(context.current)):
                self._port_action(context.current,
                                  context.bound_segment,
                                  self._configure_nxos_db)

    def update_port_postcommit(self, context):
        """Update port non-database commit event."""

        # if VM migration is occurring then remove previous nexus switch entry
        # else process update event.
        if self._is_vm_migration(context):
            self._port_action(context.original,
                              context.original_bound_segment,
                              self._delete_switch_entry)
        else:
            if (self._is_deviceowner_compute(context.current) and
                self._is_status_active(context.current)):
                self._port_action(context.current,
                                  context.bound_segment,
                                  self._configure_host_entries)

    def delete_port_precommit(self, context):
        """Delete port pre-database commit event."""
        if self._is_deviceowner_compute(context.current):
            self._port_action(context.current,
                              context.bound_segment,
                              self._delete_nxos_db)

    def delete_port_postcommit(self, context):
        """Delete port non-database commit event."""
        if self._is_deviceowner_compute(context.current):
            self._port_action(context.current,
                              context.bound_segment,
                              self._delete_switch_entry)
