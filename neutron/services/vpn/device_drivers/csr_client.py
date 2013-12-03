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
import logging  # TODO(pcm) remove once integrated in with Neutron
import requests
from webob import exc as wexc

from neutron.openstack.common import jsonutils
#from neutron.openstack.common import log as logging

# TODO(pcm): Remove this once integrated in with Neutron
if False:  # Debugging
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
        self.timeout_interval = timeout
        self.max_tries = 5

    def _contents_for(self, response, method, url):
        """Return contents from response.

        A temporary function, until the CSR fixes authentication to return
        the token via a 200 status, for which we can remove this function
        and do the check for GET and 200 in the caller.
        """
        if (('auth/token-services' in url and
             self.status == wexc.HTTPCreated.code) or
            (method == 'GET' and self.status == wexc.HTTPOk.code)):
            return response.json()

    def _request(self, method, url, attempt, **kwargs):
        """Perform REST request and save response info."""
        try:
            response = requests.request(method, url, verify=False,
                                        timeout=None,
                                        **kwargs)
        except requests.Timeout:
            self.status = wexc.HTTPRequestTimeout.code
            LOG.debug(_("%(method)s: Request timeout #%(attempt)d "
                        "(%(interval)f) for CSR(%(host)s)"),
                      {'method': method, 'attempt': attempt + 1,
                       'interval': self.timeout_interval, 'host': self.host})
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
            self.status = response.status_code
            LOG.debug(_("%(method)s: Completed [%(status)s]"),
                      {'method': method, 'status': self.status})
            return self._contents_for(response, method, url)

    def authenticated(self):
        return self.token

    def authenticate(self):
        """Obtain a token to use for subsequent CSR REST requests.

        This does not use a timeout with retry count, like _do_request(). Was
        seeing that a ConnectionError, instead of a Timeout exception occuring,
        when using a one second timeout.
        """

        url = URL_BASE % {'host': self.host, 'resource': 'auth/token-services'}
        headers = {'Content-Length': '0',
                   'Accept': 'application/json'}
        headers.update(HEADER_CONTENT_TYPE_JSON)
        self.token = None
        # QUESTION: Should we display user/password in log?
        LOG.debug(_("Authenticate request %(resource)s as %(auth)s"),
                  {'resource': url, 'auth': self.auth})
        response = self._request("POST", url, 1,
                                 headers=headers, auth=self.auth)
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

    def _do_request(self, method, resource, payload=None, more_headers=None):
        """Perform a REST request to a CSR resource.

        If this is the first time interacting with the CSR, a token will
        be obtained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more.

        If there is a timeout, we'll retry, up to the define number of
        retries, doubling the timeout interval on each try.
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
        try_num = 0
        while try_num < self.max_tries:
            response = self._request(method, url, try_num,
                                     headers=headers, data=payload)
            if self.status == wexc.HTTPUnauthorized.code:
                if not self.authenticate():
                    return
                headers['X-auth-token'] = self.token
                LOG.debug(_("%(method)s: Retry request for %(resource)s "
                            "headers %(headers)s payload %(payload)s"),
                          {'method': method.upper(), 'resource': url,
                           'payload': payload, 'headers': headers})
                return self._request(method, url, try_num,
                                     headers=headers, data=payload)
            if self.status == wexc.HTTPRequestTimeout.code:
                if not self.timeout_interval:
                    break  # Cannot retry when no interval specified
                try_num += 1
                self.timeout_interval *= 2.0
            else:
                return response
        LOG.error(_("%(method)s: Request timeout %(tries)d times "
                    "for CSR(%(host)s)"),
                  {'method': method, 'tries': try_num, 'host': self.host})

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

    content = csr.post_request('interfaces/gigabitEthernet0/statistics',
                               payload={'action': 'clear'})
    print "Good post status %s, Content=%s" % (csr.status, content)
    content = csr.post_request('no/such/request',
                               payload={'foo': 'bar'})
    print "Bad post status %s, Content=%s" % (csr.status, content)
