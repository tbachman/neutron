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

from neutron.common import constants
from neutron.extensions import portbindings
from neutron.openstack.common.gettextutils import _LE, _LW
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.ucsm import config
from neutron.plugins.ml2.drivers.cisco.ucsm import constants as const
from neutron.plugins.ml2.drivers.cisco.ucsm import ucsm_model
from neutron.plugins.ml2.drivers.cisco.ucsm import ucsm_network_driver

LOG = logging.getLogger(__name__)


class CiscoUcsmMechanismDriver(api.MechanismDriver):

    """ML2 Mechanism Driver for Cisco UCS Manager."""

    def initialize(self):
        self.vif_type = portbindings.VIF_TYPE_802_QBH
        self.vif_details = {portbindings.CAP_PORT_FILTER: False}
        self.driver = ucsm_network_driver.CiscoUcsmDriver()
        self.supported_vnic_types = [portbindings.VNIC_DIRECT,
                                     portbindings.VNIC_MACVTAP]
        self.supported_pci_devs = config.parse_pci_vendor_config()
        self.ucsm_db = ucsm_model.UcsmDbModel()

    def _get_vlanid(self, context):
        """Returns vlan_id associated with a bound VLAN segment."""
        segment = context.top_bound_segment
        if segment and self.check_segment(segment):
            return segment.get(api.SEGMENTATION_ID)

    def _check_vnic_type_and_vendor_info(self, context):
        """Checks if this vnic_type and vendor device info are supported.

        Returns True if:
        1. the port vnic_type is direct or macvtap and
        2. the vendor_id and product_id of the port is supported by
        this MD
        Useful in determining if this MD should bind the current
        port.
        """
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        # Check for vnic_type
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("Unsupported vnic_type: %s", vnic_type)
            return False

        # Check for vendor_info
        return self._check_for_supported_vendor(context)

    def _check_for_supported_vendor(self, context):
        """Checks if the port belongs to a supported vendor.

        Returns True for supported_pci_devs.
        """
        profile = context.current.get(portbindings.PROFILE, {})
        if not profile:
            LOG.debug("Port binding missing profile info")
            return False
        vendor_info = profile.get('pci_vendor_info')
        if not vendor_info:
            LOG.debug("Port binding missing pci vendor info")
            return False
        if vendor_info not in self.supported_pci_devs:
            LOG.debug("Unsupported vendor and product type %s",
                      str(vendor_info))
            return False
        return True

    def _is_vm_fex_port(self, context):
        """Checks if the port is a VMFEX port.

        Returns True only for port that support VM-FEX.
        It is important to distinguish between the two since Port Profiles
        on the UCS Manager are created only for the VM-FEX ports.
        """
        profile = context.current.get(portbindings.PROFILE, {})
        vendor_info = profile.get('pci_vendor_info')

        return vendor_info == const.PCI_INFO_CISCO_VIC_1240

    def update_port_precommit(self, context):
        """Adds port profile and vlan information to the DB.

        Assign a port profile to this port. To do that:
        1. Get the vlan_id associated with the bound segment
        2. Check if a port profile already exists for this vlan_id
        3. If yes, associate that port profile with this port.
        4. If no, create a new port profile with this vlan_id and
        associate with this port
        """
        LOG.debug("Inside update_port_precommit")
        if not self._check_vnic_type_and_vendor_info(context):
            LOG.debug("update_port_precommit aborting due to unsupported "
                      "vnic_type or vendor")
            return
        # If this is an Intel SR-IOV vnic, then no need to create port
        # profile on the UCS manager. So no need to update the DB.
        if not self._is_vm_fex_port(context):
            LOG.debug("update_port_precommit has nothing to do for this "
                      "sr-iov port")
            return

        vlan_id = self._get_vlanid(context)

        if not vlan_id:
            LOG.warn(_LW("update_port_precommit: vlan_id is None"))
            return

        p_profile_name = self.make_profile_name(vlan_id)
        LOG.debug("update_port_precommit: Profile: %s, VLAN_id: %d",
                  p_profile_name, vlan_id)

        if not self.ucsm_db.get_port_profile_for_vlan(vlan_id):
            # Create a new port profile entry in the db
            self.ucsm_db.add_port_profile(p_profile_name, vlan_id)

    def update_port_postcommit(self, context):
        """Creates a port profile on UCS Manager.

        Creates a Port Profile for this VLAN if it does not already
        exist.
        """
        LOG.debug("Inside update_port_postcommit")
        vlan_id = self._get_vlanid(context)

        if not vlan_id:
            LOG.warn(_LW("update_port_postcommit: vlan_id is None."))
            return

        profile_name = self.ucsm_db.get_port_profile_for_vlan(vlan_id)

        # Check if UCS Manager needs to create a Port Profile.
        # 1. Make sure update_port_precommit added an entry in the DB
        # for this port profile
        # 2. Make sure this is a vm_fex_port.(Port profiles are created
        # only for VM-FEX ports.)
        # 3. Make sure that the Port Profile hasn't already been created.

        if not self._is_vm_fex_port(context):
            LOG.debug("update_port_postcommit: No need to create Port Profile "
                      "for vlan_id %d", vlan_id)
            return

        if self.ucsm_db.is_port_profile_created(vlan_id):
            LOG.debug("update_port_postcommit: Port Profile %s for vlan_id %d "
                      "already exists. Nothing to do.", profile_name, vlan_id)
            return

        # Ask the UCS Manager driver to create the above Port Profile.
        # Connection to the UCS Manager is managed from within the driver.
        if self.driver.create_portprofile(profile_name, vlan_id):
            # Port profile created on UCS, record that in the DB.
            self.ucsm_db.set_port_profile_created(vlan_id, profile_name)

    def bind_port(self, context):
        """Binds port to current network segment.

        Binds port only if the vnic_type is direct or macvtap and
        the port is from a supported vendor. While binding port set it
        in ACTIVE state and provide the Port Profile or Vlan Id as part
        vif_details.
        """
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        LOG.debug("Attempting to bind port %(port)s with vnic_type "
                  "%(vnic_type)s on network %(network)s",
                  {'port': context.current['id'],
                   'vnic_type': vnic_type,
                   'network': context.network.current['id']})

        if not self._check_vnic_type_and_vendor_info(context):
            return

        for segment in context.network.network_segments:
            if self.check_segment(segment):
                vlan_id = segment[api.SEGMENTATION_ID]

                if not vlan_id:
                    LOG.warn(_LW("Bind port: vlan_id is None."))
                    return

                LOG.debug("Port binding to Vlan_id: %s", str(vlan_id))

                # Check if this is a Cisco VM-FEX port or Intel SR_IOV port
                if self._is_vm_fex_port(context):
                    profile_name = self.make_profile_name(vlan_id)
                    self.vif_details[
                        portbindings.VIF_DETAILS_PROFILEID] = profile_name
                else:
                    self.vif_details[
                        portbindings.VIF_DETAILS_VLAN] = str(vlan_id)

                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.vif_details,
                                    constants.PORT_STATUS_ACTIVE)
                return

        LOG.error(_LE("UCS Mech Driver: Failed binding port ID %(id)s "
                      "on any segment of network %(network)s"),
                  {'id': context.current['id'],
                   'network': context.network.current['id']})

    @staticmethod
    def check_segment(segment):
        network_type = segment[api.NETWORK_TYPE]
        return network_type == p_const.TYPE_VLAN

    @staticmethod
    def make_profile_name(vlan_id):
        return const.PORT_PROFILE_NAME_PREFIX + str(vlan_id)
