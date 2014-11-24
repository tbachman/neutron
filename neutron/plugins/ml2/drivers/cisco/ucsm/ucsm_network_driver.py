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

from neutron.openstack.common.gettextutils import _LE
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.cisco.ucsm import constants as const
from neutron.plugins.ml2.drivers.cisco.ucsm import exceptions as cexc

LOG = logging.getLogger(__name__)


class CiscoUcsmDriver(object):

    """UCS Manager Driver Main Class."""

    def __init__(self):
        LOG.debug("UCS Manager Network driver found")
        self.ucsmsdk = None
        self.ucsm_ip = cfg.CONF.ml2_cisco_ucsm.ucsm_ip
        self.username = cfg.CONF.ml2_cisco_ucsm.ucsm_username
        self.password = cfg.CONF.ml2_cisco_ucsm.ucsm_password

        LOG.debug("UCS Manager Network driver Ip: %s", self.ucsm_ip)
        self.handles = {}

    def _validate_config(self):
        if not cfg.CONF.ml2_cisco_ucsm.get('ucsm_ip'):
            msg = _('UCS Manager IP address is not provided')
            LOG.error(msg)
        if not cfg.CONF.ml2_cisco_ucsm.get('ucsm_username'):
            msg = _('UCS Manager username is not provided')
            LOG.error(msg)

    def _import_ucsmsdk(self):
        """Imports the Ucsm SDK module.

        This module is not installed as part of the normal Neutron
        distributions. It is imported dynamically in this module so that
        the import can be mocked, allowing unit testing without requiring
        the installation of UcsSdk.

        """
        return importutils.import_module('UcsSdk')

    def ucs_manager_connect(self):
        """Connects to a UCS Manager."""
        self._validate_config()

        if not self.ucsmsdk:
            self.ucsmsdk = self._import_ucsmsdk()

        handle = self.ucsmsdk.UcsHandle()
        try:
            handle.Login(self.ucsm_ip, self.username, self.password)
            self.handles[self.ucsm_ip] = handle
        except Exception as e:
            # Raise a Neutron exception. Include a description of
            # the original  exception.
            raise cexc.UcsmConnectFailed(ucsm_ip=self.ucsm_ip, exc=e)

        return self.handles[self.ucsm_ip]

    def _get_all_portprofiles(self, handle):
        """Gets all port profiles from a specific UCS Manager."""

        # Get Managed Object VnicProfile
        try:
            port_profile = handle.GetManagedObject(
                None,
                self.ucsmsdk.VnicProfile.ClassId())

        except Exception as e:
            # Raise a Neutron exception. Include a description of
            # the original  exception.
            raise cexc.UcsmConfigReadFailed(ucsm_ip=self.ucsm_ip, exc=e)
        return port_profile

    def _create_vlanprofile(self, handle, vlan_id):
        """Creates VLAN profile to be assosiated with the Port Profile."""
        vlan_name = self.make_vlan_name(vlan_id)
        vlan_profile_dest = (const.VLAN_PATH + const.VLAN_PROFILE_PATH_PREFIX +
                             vlan_name)
        LOG.debug("Creating Vlan Profile: %s", vlan_name)

        try:
            vp1 = handle.GetManagedObject(
                None,
                self.ucsmsdk.FabricLanCloud.ClassId(),
                {self.ucsmsdk.FabricLanCloud.DN: const.VLAN_PATH})
            if not vp1:
                LOG.debug("UCS Manager network driver Vlan Profile "
                          "path at %s missing", const.VLAN_PATH)
                return False

            #Create a vlan profile with the given vlan_id
            vp2 = handle.AddManagedObject(
                vp1,
                self.ucsmsdk.FabricVlan.ClassId(),
                {self.ucsmsdk.FabricVlan.COMPRESSION_TYPE:
                 const.VLAN_COMPRESSION_TYPE,
                 self.ucsmsdk.FabricVlan.DN: vlan_profile_dest,
                 self.ucsmsdk.FabricVlan.SHARING: "none",
                 self.ucsmsdk.FabricVlan.PUB_NW_NAME: "",
                 self.ucsmsdk.FabricVlan.ID: str(vlan_id),
                 self.ucsmsdk.FabricVlan.MCAST_POLICY_NAME: "",
                 self.ucsmsdk.FabricVlan.NAME: vlan_name,
                 self.ucsmsdk.FabricVlan.DEFAULT_NET: "no"})
            if not vp2:
                LOG.debug("UCS Manager network driver could not create Vlan "
                          "Profile %s at %s", vlan_name, vlan_profile_dest)
                return False

            LOG.debug("UCS Manager network driver created Vlan Profile %s "
                      "at %s", vlan_name, vlan_profile_dest)
            return True

        except Exception as e:
            # Raise a Neutron exception. Include a description of
            # the original  exception.
            raise cexc.UcsmConfigFailed(config=vlan_name,
                                        ucsm_ip=self.ucsm_ip, exc=e)

    def _create_port_profile(self, handle, profile_name, vlan_id):
        """Creates a Port Profile on the UCS Manager.

        Significant parameters set in the port profile are:
        1. Port profile name - Should match what was set in vif_details
        2. High performance mode - For VM-FEX to be enabled/configured on
        the port using this port profile, this mode should be enabled.
        3. Vlan id - Vlan id used by traffic to and from the port.
        """
        port_profile_dest = (const.PORT_PROFILESETDN + const.VNIC_PATH_PREFIX +
                             profile_name)
        # Max ports that this port profile can be applied to
        max_ports = 64

        vlan_name = self.make_vlan_name(vlan_id)
        vlan_associate_path = (const.PORT_PROFILESETDN +
                               const.VNIC_PATH_PREFIX + profile_name +
                               const.VLAN_PATH_PREFIX + vlan_name)
        cl_profile_name = const.CLIENT_PROFILE_NAME_PREFIX + str(vlan_id)
        cl_profile_dest = (const.PORT_PROFILESETDN + const.VNIC_PATH_PREFIX +
                           profile_name + const.CLIENT_PROFILE_PATH_PREFIX +
                           cl_profile_name)

        LOG.debug("Creating Port Profile: %s", profile_name)

        try:
            port_profile = handle.GetManagedObject(
                None,
                self.ucsmsdk.VnicProfileSet.ClassId(),
                {self.ucsmsdk.VnicProfileSet.DN: const.PORT_PROFILESETDN})

            if not port_profile:
                LOG.debug("UCS Manager network driver Port Profile path at "
                          "%s missing", const.PORT_PROFILESETDN)
                return False

            LOG.debug("UCS Manager network driver creating Port Profile at ",
                      "path %s", port_profile_dest)

            # Create a port profile on the UCS Manager
            p_profile = handle.AddManagedObject(
                port_profile,
                self.ucsmsdk.VnicProfile.ClassId(),
                {self.ucsmsdk.VnicProfile.NAME: profile_name,
                 self.ucsmsdk.VnicProfile.POLICY_OWNER: "local",
                 self.ucsmsdk.VnicProfile.NW_CTRL_POLICY_NAME: "",
                 self.ucsmsdk.VnicProfile.PIN_TO_GROUP_NAME: "",
                 self.ucsmsdk.VnicProfile.DN: port_profile_dest,
                 self.ucsmsdk.VnicProfile.DESCR: const.DESCR,
                 self.ucsmsdk.VnicProfile.QOS_POLICY_NAME: "",
                 self.ucsmsdk.VnicProfile.HOST_NW_IOPERF: "none",
                 self.ucsmsdk.VnicProfile.MAX_PORTS: max_ports})
            if not p_profile:
                LOG.debug("UCS Manager network driver could not create Port "
                          "Profile %s at %s", profile_name, port_profile_dest)
                return False

            LOG.debug("UCS Manager network driver associating Vlan Profile "
                      "with Port Profile at %s", vlan_associate_path)
            # Associate port profile with vlan profile
            mo = handle.AddManagedObject(
                p_profile,
                self.ucsmsdk.VnicEtherIf.ClassId(),
                {self.ucsmsdk.VnicEtherIf.DN: vlan_associate_path,
                 self.ucsmsdk.VnicEtherIf.NAME: vlan_name,
                 self.ucsmsdk.VnicEtherIf.DEFAULT_NET: "yes"}, True)
            if not mo:
                LOG.debug("UCS Manager network driver cannot associate Vlan "
                          "Profile %s to Port Profile %s", vlan_name,
                          profile_name)
                return False

            LOG.debug("UCS Manager network driver created Port Profile %s "
                      "at %s", profile_name, port_profile_dest)

            cl_profile = handle.AddManagedObject(
                p_profile,
                self.ucsmsdk.VmVnicProfCl.ClassId(),
                {self.ucsmsdk.VmVnicProfCl.ORG_PATH: ".*",
                 self.ucsmsdk.VmVnicProfCl.DN: cl_profile_dest,
                 self.ucsmsdk.VmVnicProfCl.NAME: cl_profile_name,
                 self.ucsmsdk.VmVnicProfCl.POLICY_OWNER: "local",
                 self.ucsmsdk.VmVnicProfCl.SW_NAME: ".*",
                 self.ucsmsdk.VmVnicProfCl.DC_NAME: ".*",
                 self.ucsmsdk.VmVnicProfCl.DESCR: const.DESCR})
            if not cl_profile:
                LOG.debug("UCS Manager network driver could not create Client "
                          "Profile %s at %s", cl_profile_name, cl_profile_dest)
                return False

            LOG.debug("UCS Manager network driver created Client Profile %s "
                      "at %s", cl_profile_name, cl_profile_dest)
            return True

        except Exception as e:
            # Raise a Neutron exception. Include a description of
            # the original  exception.
            raise cexc.UcsmConfigFailed(config=profile_name,
                                        ucsm_ip=self.ucsm_ip, exc=e)

    def create_portprofile(self, profile_name, vlan_id):
        """Top level method to create Port Profiles on the UCS Manager.

        Calls all the methods responsible for the individual tasks that
        ultimately result in the creation of the Port Profile on the UCS
        Manager.
        """
        # Connect to UCS Manager
        handle = self.ucs_manager_connect()
        if not handle:
            LOG.error(_LE('UCS Manager network driver failed to connect '
                          'to UCS Manager.'))
            return False

        try:
            handle.StartTransaction()
            # Create Vlan Profile
            if not self._create_vlanprofile(handle, vlan_id):
                LOG.error(_LE('UCS Manager network driver failed to create '
                              'Vlan Profile for vlan %s'), str(vlan_id))
                return False

            # Create Port Profile
            if not self._create_port_profile(handle, profile_name, vlan_id):
                LOG.error(_LE('UCS Manager network driver failed to create '
                              'Port Profile %s'), profile_name)
                return False

            # Everything went fine.Yay!!
            return True
        finally:
            handle.CompleteTransaction()
            # Disconnect from UCS Manager
            self.ucs_manager_disconnect()

    def ucs_manager_disconnect(self):
        """Disconnects from the UCS Manager.

        After the disconnect, the handle associated with this connection
        is no longer valid.
        """
        handle = self.handles[self.ucsm_ip]
        handle.Logout()

    @staticmethod
    def make_vlan_name(vlan_id):
        return const.VLAN_PROFILE_NAME_PREFIX + str(vlan_id)
