# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
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
# @author: Paul Michali, Cisco Systems, Inc.
import requests
from requests.exceptions import ConnectionError, Timeout, SSLError
from webob import exc as wexc

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging


# TODO(pcm): Set to 2.0, once resolve issues with CSR slowness and
# timeout handling for PUT operations, which are taking up to 6 secs.
# Should take 1.x seconds.
TIMEOUT = 7.0

# TODO(pcm): Redesign for asynchronous operation.

LOG = logging.getLogger(__name__)
HEADER_CONTENT_TYPE_JSON = {'content-type': 'application/json'}
URL_BASE = 'https://%(host)s/api/v1/%(resource)s'


class CsrRestClient(object):

    """REST CsrRestClient for accessing the Cisco Cloud Services Router."""

    def __init__(self, host, username, password, timeout=None):
        self.host = host
        self.auth = (username, password)
        self.token = None
        self.status = wexc.HTTPOk.code
        self.timeout = timeout
        self.max_tries = 5

    def _response_info_for(self, response, method, url):
        """Return contents or location from response.

        Temporary check of 201 for an authentication POST response,
        where we want to return the token. In the future, the CSR will
        return this as a 200, and the special test here can be removed.

        For a POST with a 201 response, we return the header's location,
        which contains the identifier for the created resource.

        If there is an error, we'll return the response content, so that
        it can be used in error processing ('error-code', 'error-message',
        and 'detail' fields).
        """
        if (('auth/token-services' in url and
             self.status == wexc.HTTPCreated.code) or
            (method == 'GET' and self.status == wexc.HTTPOk.code)):
            return response.json()
        if method == 'POST' and self.status == wexc.HTTPCreated.code:
            return response.headers.get('location', '')
        if self.status >= wexc.HTTPBadRequest.code and response.content:
            if 'error-code' in response.content:
                content = jsonutils.loads(response.content)
                LOG.debug("Error response content %s", content)
                return content
        # LOG.debug("Response content %s", response.content)

    def _request(self, method, url, **kwargs):
        """Perform REST request and save response info."""
        try:
            LOG.debug(_("%(method)s: Request for %(resource)s headers: "
                        "%(headers)s payload: %(payload)s"),
                      {'method': method.upper(), 'resource': url,
                       'payload': kwargs.get('data'),
                       'headers': kwargs.get('headers')})
            response = requests.request(method, url, verify=False,
                                        timeout=self.timeout, **kwargs)
        except (Timeout, SSLError) as te:
            # Should never see SSLError, unless requests package is old (<2.0)
            LOG.warning(_("%(method)s: Request timeout%(ssl)s "
                          "(%(timeout).3f sec) for CSR(%(host)s)"),
                        {'method': method,
                         'timeout': self.timeout if not None else '0.0',
                         'ssl': '(SSLError)'
                         if isinstance(te, SSLError) else '',
                         'host': self.host})
            self.status = wexc.HTTPRequestTimeout.code
        except ConnectionError as ce:
            LOG.error(_("%(method)s: Unable to connect to CSR(%(host)s): "
                        "%(error)s"),
                      {'method': method, 'host': self.host, 'error': ce})
            self.status = wexc.HTTPNotFound.code
        except Exception as e:
            LOG.error(_("%(method)s: Unexpected error for CSR (%(host)s): "
                        "%(error)s"),
                      {'method': method, 'host': self.host, 'error': e})
            self.status = wexc.HTTPInternalServerError.code
        else:
            self.status = response.status_code
            LOG.debug(_("%(method)s: Completed [%(status)s]"),
                      {'method': method, 'status': self.status})
            return self._response_info_for(response, method, url)

    def authenticated(self):
        return self.token

    def authenticate(self):
        """Obtain a token to use for subsequent CSR REST requests."""

        url = URL_BASE % {'host': self.host, 'resource': 'auth/token-services'}
        headers = {'Content-Length': '0',
                   'Accept': 'application/json'}
        headers.update(HEADER_CONTENT_TYPE_JSON)
        self.token = None
        # QUESTION: Should we display user/password in log?
        LOG.debug(_("Authenticating request %(resource)s as %(auth)s"),
                  {'resource': url, 'auth': self.auth})
        response = self._request("POST", url, headers=headers, auth=self.auth)
        if response:
            self.token = response['token-id']
            # QUESTION: Should we display token in log?
            LOG.debug(_("Authenticated with CSR(%(host)s). "
                        "Token=%(token)s"),
                      {'host': self.host, 'token': self.token})
            return True
        LOG.error(_("Failed authentication with CSR (%(host)s) "
                    "[%(status)s]"),
                  {'host': self.host, 'status': self.status})

    def _do_request(self, method, resource, payload=None, more_headers=None,
                    full_url=False):
        """Perform a REST request to a CSR resource.

        If this is the first time interacting with the CSR, a token will
        be obtained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more.
        """

        if not self.authenticated():
            if not self.authenticate():
                return

        if full_url:
            url = resource
        else:
            url = ('https://%(host)s/api/v1/%(resource)s' %
                   {'host': self.host, 'resource': resource})
        headers = {'Accept': 'application/json', 'X-auth-token': self.token}
        if more_headers:
            headers.update(more_headers)
        if payload:
            payload = jsonutils.dumps(payload)
        response = self._request(method, url, data=payload, headers=headers)
        if self.status == wexc.HTTPUnauthorized.code:
            if not self.authenticate():
                return
            headers['X-auth-token'] = self.token
            response = self._request(method, url, data=payload,
                                     headers=headers)
        if self.status != wexc.HTTPRequestTimeout.code:
            return response
        LOG.error(_("%(method)s: Request timeout for CSR(%(host)s)"),
                  {'method': method, 'host': self.host})

    def get_request(self, resource, full_url=False):
        """Perform a REST GET requests for a CSR resource."""
        return self._do_request('GET', resource, full_url=full_url)

    def post_request(self, resource, payload=None):
        """Perform a POST request to a CSR resource."""
        return self._do_request('POST', resource, payload=payload,
                                more_headers=HEADER_CONTENT_TYPE_JSON)

    def put_request(self, resource, payload=None):
        """Perform a PUT request to a CSR resource."""
        return self._do_request('PUT', resource, payload=payload,
                                more_headers=HEADER_CONTENT_TYPE_JSON)

    def delete_request(self, resource):
        """Perform a DELETE request on a CSR resource."""
        return self._do_request('DELETE', resource,
                                more_headers=HEADER_CONTENT_TYPE_JSON)

    def create_ike_policy(self, policy_info):
        base_ike_policy_info = {u'version': u'v1',
                                u'local-auth-method': u'pre-share'}
        base_ike_policy_info.update(policy_info)
        return self.post_request('vpn-svc/ike/policies',
                                 payload=base_ike_policy_info)

    def create_ipsec_policy(self, policy_info):
        base_ipsec_policy_info = {u'mode': u'tunnel',
                                  u'anti-replay-window-size': u'Disable'}
        base_ipsec_policy_info.update(policy_info)
        return self.post_request('vpn-svc/ipsec/policies',
                                 payload=base_ipsec_policy_info)

    def create_pre_shared_key(self, psk_info):
        return self.post_request('vpn-svc/ike/keyrings', payload=psk_info)

    def create_ipsec_connection(self, connection_info):
        base_connection_info = {u'vpn-type': u'site-to-site',
                                u'ip-version': u'ipv4'}
        connection_info.update(base_connection_info)
        return self.post_request('vpn-svc/site-to-site',
                                 payload=connection_info)

    def configure_ike_keepalive(self, keepalive_info):
        base_keepalive_info = {u'periodic': True}
        keepalive_info.update(base_keepalive_info)
        return self.put_request('vpn-svc/ike/keepalive', keepalive_info)

if __name__ == '__main__':
    csr = CsrRestClient('192.168.200.20', 'stack', 'cisco')

    content = csr.post_request('interfaces/gigabitEthernet0/statistics',
                               payload={'action': 'clear'})
    print "Good post status %s, Content=%s" % (csr.status, content)
    content = csr.post_request('no/such/request',
                               payload={'foo': 'bar'})
    print "Bad post status %s, Content=%s" % (csr.status, content)
