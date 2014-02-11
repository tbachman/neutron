# Copyright (c) 2014 Cisco Systems
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
#
# @author: Henry Gessau, Cisco Systems

"""Exceptions used by Cisco Nexus ML2 mechanism driver."""

from neutron.common import exceptions


class ApicHostNoResponse(exceptions.NotFound):
    """No response from the APIC via the specified URL."""
    message = _("No response from APIC at %(url)s")


class ApicResponseNotOk(exceptions.NeutronException):
    """A response from the APIC was not HTTP OK."""
    message = _("APIC responded with HTTP status %(status)s: %(reason)s, "
                "Request: '%(request)s', "
                "APIC error code %(err_code)s: %(err_text)s")

    def __init__(self, **kwargs):
        """Save the error information from the APIC."""
        self.http_request = kwargs['request']
        self.http_response_code = kwargs['status']
        self.http_response_reason = kwargs['reason']
        self.apic_err_code = kwargs['err_code']
        self.apic_err_text = kwargs['err_text']
        super(ApicResponseNotOk, self).__init__(**kwargs)


class ApicSessionNotLoggedIn(exceptions.NotAuthorized):
    """Attempted APIC operation while not logged in to APIC."""
    message = _("Authorized APIC session not established")
