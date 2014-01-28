
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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
# @author: Swaminathan Vasudevan, Hewlett-Packard

from neutron.api.v2 import attributes as attrs
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import servicetype_db as st_db
from neutron.db.vpn import vpn_db
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services import provider_configuration as pconf
from neutron.services import service_base

LOG = logging.getLogger(__name__)


class VPNPlugin(vpn_db.VPNPluginDb):

    """Implementation of the VPN Service Plugin.

    This class manages the workflow of VPNaaS request/response.
    Most DB related works are implemented in class
    vpn_db.VPNPluginDb.
    """
    supported_extension_aliases = ["vpnaas"]


class VPNDriverPlugin(VPNPlugin, vpn_db.VPNPluginRpcDbMixin):
    """VpnPlugin which supports VPN Service Drivers."""
    #TODO(nati) handle ikepolicy and ipsecpolicy update usecase
    supported_extension_aliases = ["vpnaas", "service-type"]

    def __init__(self):
        """Initialization for the vpn service plugin."""

        super(VPNDriverPlugin, self).__init__()
        self.service_type_manager = st_db.ServiceTypeManager.get_instance()
        self._load_drivers()

    def _load_drivers(self):
        """Loads plugin-drivers specified in configuration."""
        self.drivers, self.default_provider = service_base.load_drivers(
            constants.VPN, self)
        ctx = context.get_admin_context(load_admin_roles=False)
        # check status of the services if they have lost their providers
        self._check_orphan_vpnservice_associations(ctx, self.drivers.keys())

    def _get_driver_for_vpnservice(self, context, resource):
        provider_name = resource['provider']
        return self.drivers[provider_name]

    def _get_driver_for_ipsec_site_connection(self, context, resource):
        vpnservice = self.get_vpnservice(
            context, resource['vpnservice_id'])
        provider_name = vpnservice['provider']
        return self.drivers[provider_name]

    def _check_orphan_vpnservice_associations(self, context, provider_names):
        """Ensure no orphaned providers for existing services.

        Administrator should delete all associations
        before removing a provider.
        """
        vpnservices = self.get_vpnservices(context)
        lost_providers = set([vpnservice['provider']
                              for vpnservice in vpnservices
                              if vpnservice['provider'] not in provider_names])
        if lost_providers:
            msg = _("Delete associated vpnservices "
                    "before removings providers %s") % list(lost_providers)
            LOG.exception(msg)
            raise SystemExit(msg)

    def _get_provider_name(self, context, vpnservice):
        if attrs.is_attr_set(vpnservice.get('provider')):
            provider_name = pconf.normalize_provider_name(
                vpnservice['provider'])
            self.validate_provider(provider_name)
            return provider_name

        if not self.default_provider:
            raise n_exc.InvalidInput(
                error_message=_("No default provider specified "
                                "for VPN Service %s") % vpnservice['id'])
        return self.default_provider

    def create_vpnservice(self, context, vpnservice):
        provider_name = self._get_provider_name(
            context, vpnservice['vpnservice'])
        with context.session.begin(subtransactions=True):
            service = super(VPNDriverPlugin, self).create_vpnservice(
                context, vpnservice)
            self.service_type_manager.add_resource_association(
                context,
                constants.VPN,
                provider_name, service['id'])

        #need to add provider name to vpnservice dict,
        #because provider was not known to db plugin at vpnservice creation
        service['provider'] = provider_name
        driver = self.drivers[provider_name]
        driver.create_vpnservice(context, service)
        return service

    def validate_provider(self, provider):
        if provider not in self.drivers:
            raise n_exc.InvalidInput(
                error_message=_("No provider with name '%s' found.") %
                provider)

    def update_vpnservice(self, context, id, vpnservice):
        old_vpnservice = self.get_vpnservice(context, id)
        updated_vpnservice = super(VPNDriverPlugin, self).update_vpnservice(
            context, id, vpnservice)
        driver = self._get_driver_for_vpnservice(context, updated_vpnservice)
        driver.update_vpnservice(context, old_vpnservice, updated_vpnservice)
        return updated_vpnservice

    def delete_vpnservice(self, context, id):
        vpnservice = self.get_vpnservice(context, id)
        self.service_type_manager.del_resource_associations(context, [id])
        super(VPNDriverPlugin, self).delete_vpnservice(context, id)
        driver = self._get_driver_for_vpnservice(context, vpnservice)
        driver.delete_vpnservice(context, vpnservice)

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        ipsec_site_connection = super(
            VPNDriverPlugin, self).create_ipsec_site_connection(
                context, ipsec_site_connection)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.create_ipsec_site_connection(context, ipsec_site_connection)
        return ipsec_site_connection

    def delete_ipsec_site_connection(self, context, ipsec_conn_id):
        ipsec_site_connection = self.get_ipsec_site_connection(
            context, ipsec_conn_id)
        super(VPNDriverPlugin, self).delete_ipsec_site_connection(
            context, ipsec_conn_id)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.delete_ipsec_site_connection(context, ipsec_site_connection)

    def update_ipsec_site_connection(
            self, context,
            ipsec_conn_id, ipsec_site_connection):
        old_ipsec_site_connection = self.get_ipsec_site_connection(
            context, ipsec_conn_id)
        ipsec_site_connection = super(
            VPNDriverPlugin, self).update_ipsec_site_connection(
                context,
                ipsec_conn_id,
                ipsec_site_connection)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.update_ipsec_site_connection(
            context, old_ipsec_site_connection, ipsec_site_connection)
        return ipsec_site_connection
