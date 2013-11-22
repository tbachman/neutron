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
import logging
import requests
from webob import exc as wexc

from neutron.openstack.common import jsonutils
#from neutron.openstack.common import log as logging


if True:  # Debugging
    logging.basicConfig(format='%(asctime)-15s [%(levelname)s] %(message)s',
                        level=logging.DEBUG)

LOG = logging.getLogger(__name__)
HEADER_CONTENT_TYPE_JSON = {'content-type': 'application/json'}
URL_BASE = 'https://%(host)s/api/v1/%(resource)s'


class Client(object):

    """REST Client for accessing the Cisco Cloud Services Router."""

    def __init__(self, host, username, password, timeout=None):
        self.host = host
        self.auth = (username, password)
        self.token = None
        self.status = wexc.HTTPOk.code
        self.timeout = timeout

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
        LOG.debug(_("Authenticate request %(resource)s as %(auth)s"),
                  {'resource': url, 'auth': self.auth})
        try:
            r = requests.post(url, headers=headers, timeout=self.timeout,
                              auth=self.auth, verify=False)
        except requests.ConnectionError as ce:
            LOG.error(_("Unable to connect to CSR(%(host)s): %(error)s"),
                      {'host': self.host, 'error': ce})
            self.status = wexc.HTTPNotFound.code
        except requests.Timeout as te:
            LOG.error(_("Timeout connecting to CSR(%s(host)): %(error)s"),
                      {'host': self.host, 'error': te})
            self.status = wexc.HTTPRequestTimeout.code
        else:
            self.status = r.status_code
            # TODO(pcm): When CSR fixes this, change to 200 code
            if self.status == wexc.HTTPCreated.code:
                self.token = r.json()['token-id']
                # QUESTION: Should we display token in log?
                LOG.debug(_("Authenticated with CSR(%(host)s). "
                            "Token '%(token)s'"),
                          {'host': self.host, 'token': self.token})
                return True
            else:
                LOG.error(_("Failed authentication with CSR (%(host)s)"
                            "[%(status)s]"),
                          {'host': self.host, 'status': self.status})

    def _do_request(self, method, resource, payload=None, more_headers=None):
        """Perform a REST request to a CSR resource.

        If this is the first time interacting with the CSR, a token will
        be obtained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more.
        """

        if not self.authenticated():
            if not self.authenticate():
                return None

        url = 'https://%(host)s/api/v1/%(resource)s' % {'host': self.host,
                                                        'resource': resource}
        headers = {'Accept': 'application/json', 'X-auth-token': self.token}
        if more_headers:
            headers.update(more_headers)
        LOG.debug(_("%(method)s: Request for %(resource)s headers "
                    "%(headers)s payload %(payload)s"),
                  {'method': method.upper(), 'resource': url,
                   'payload': payload, 'headers': headers})
        if payload:
            payload = jsonutils.dumps(payload)
        try:
            r = requests.request(method, url, headers=headers,
                                 verify=False, timeout=self.timeout,
                                 data=payload)
            if r.status_code == wexc.HTTPUnauthorized.code:
                if not self.authenticate():
                    return
                headers['X-auth-token'] = self.token
                r = requests.request(method, url, headers=headers,
                                     verify=False, timeout=self.timeout,
                                     data=payload)
        except requests.Timeout as te:
            LOG.error(_("%(method)s: Request timeout for CSR(%(host)s): "
                        "%(error)s"),
                      {'method': method, 'host': self.host, 'error': te})
            self.status = wexc.HTTPRequestTimeout.code
        except requests.ConnectionError as ce:
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
            self.status = r.status_code
            LOG.debug(_("%(method)s: Completed [%(status)s]"),
                      {'method': method, 'status': self.status})
            if method == 'GET' and self.status == wexc.HTTPOk.code:
                return r.json()

    def get_request(self, resource):
        """Perform a REST GET requests for a CSR resource."""
        return self._do_request('GET', resource)

    def post_request(self, resource, payload=None):
        """Perform a POST request to a CSR resource."""
        self._do_request('POST', resource, payload=payload,
                         more_headers=HEADER_CONTENT_TYPE_JSON)

    def put_request(self, resource, payload=None):
        """Perform a PUT request to a CSR resource."""
        self._do_request('PUT', resource, payload=payload,
                         more_headers=HEADER_CONTENT_TYPE_JSON)

    def delete_request(self, resource):
        """Perform a DELETE request on a CSR resource."""
        self._do_request('DELETE', resource,
                         more_headers=HEADER_CONTENT_TYPE_JSON)


if __name__ == '__main__':
    csr = Client('192.168.200.20', 'stack', 'cisco')

#     print "Start"
#     content = csr.get_request('global/host-name')
#     print "Status:", csr.status
#     print content
#     print "End"
#
#     print "Get token: ", csr.authenticate()
#     print 'Token status %s, token=%s' %(csr.status, csr.token)
#
#     content = csr.get_request('global/host-name')
#     print "Get status %s, Content=%s" % (csr.status, content)
#
#     content = csr.get_request('global/local-users')
#     print "Get status %s, Content=%s" % (csr.status, content)
#
#     bad_host = Client('192.168.200.30', 'stack', 'cisco')
#     print "Get token: ", bad_host.authenticate()
#     print 'Bad status %s' % bad_host.status

    content = csr.post_request('interfaces/gigabitEthernet0/statistics',
                               payload={'action': 'clear'})
    print "Good post status %s, Content=%s" % (csr.status, content)
    content = csr.post_request('no/such/request',
                               payload={'foo': 'bar'})
    print "Bad post status %s, Content=%s" % (csr.status, content)
