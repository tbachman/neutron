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
from webob import exc as wexc

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class Client(object):

    """REST Client for accessing the Cisco Cloud Services Router."""

    def __init__(self, host, username, password, timeout=None):
        self.host = host
        self.auth = (username, password)
        self.token = None
        self.status = wexc.HTTPOk.code
        self.timeout = timeout

    def logged_in(self):
        return self.token

    def login(self):
        """Obtain a token to use for subsequent CSR REST requests."""

        url = 'https://%s/api/v1/auth/token-services' % self.host
        headers = {'content-type': 'application/json',
                   'Content-Length': '0',
                   'Accept': 'application/json'}
        self.token = None
        # print "Login request", url, headers, self.auth
        try:
            r = requests.post(url, headers=headers, timeout=self.timeout,
                              auth=self.auth, verify=False)
        except requests.ConnectionError as ce:
            LOG.error(_("Unable to connect to CSR (%(host)s): %(error)s"),
                      {'host': self.host, 'error': ce})
            self.status = wexc.HTTPNotFound.code
        except requests.Timeout as te:
            LOG.error(_("Timeout connecting to CSR (%s(host)): %(error)s"),
                      {'host': self.host, 'error': te})
            self.status = wexc.HTTPRequestTimeout.code
        else:
            self.status = r.status_code
            # TODO(pcm): When CSR fixes this, change to 200 code
            if self.status == wexc.HTTPCreated.code:
                self.token = r.json()['token-id']
                # print "LOG: Login successful. Token=", self.token
                return True
            else:
                LOG.error(_("Login to CSR (%(host)s) failed with status "
                            "%(status)s"),
                          {'host': self.host, 'status': self.status})

    def get_request(self, resource):
        """Perform a REST GET requests for a CSR resource.

        If this is the first time interacting with the CSR, a token will
        be obtained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more.
        """

        if not self.logged_in():
            if not self.login():
                return None

        url = 'https://%(host)s/api/v1/%(resource)s' % {'host': self.host,
                                                        'resource': resource}
        headers = {'Accept': 'application/json',
                   'X-auth-token': self.token}
        # print "GET request", url, headers
        try:
            r = requests.get(url, headers=headers,
                             verify=False, timeout=self.timeout)
            if r.status_code == wexc.HTTPUnauthorized.code:
                if not self.login():
                    return None
                headers['X-auth-token'] = self.token
                r = requests.get(url, headers=headers,
                                 verify=False, timeout=self.timeout)
        except requests.Timeout as te:
            LOG.error(_("GET timeout for CSR (%(host)s): %s"),
                      {'host': self.host, 'error': te})
            self.status = wexc.HTTPRequestTimeout.code
        except Exception as e:
            LOG.error(_("Unexpected exception during GET for CSR "
                        "(%(host)s): %(error)s"),
                      {'host': self.host, 'error': e})
            self.status = wexc.HTTPInternalServerError.code
        else:
            self.status = r.status_code
            if self.status == wexc.HTTPOk.code:
                return r.json()

    def post_request(self, resource, payload=None):
        """Perform a POST request to a CSR resource.

        If this is the first time interacting with the CSR, a token will
        be obatained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more.
        """

        if not self.logged_in():
            if not self.login():
                return None

        url = 'https://%(host)s/api/v1/%(resource)s' % {'host': self.host,
                                                        'resource': resource}
        data = jsonutils.dumps(payload)
        headers = {'Accept': 'application/json',
                   'content-type': 'application/json',
                   'X-auth-token': self.token}
        # print "POST request", url, headers, payload
        try:
            r = requests.post(url, headers=headers, data=data,
                              verify=False, timeout=self.timeout)
            if r.status_code == wexc.HTTPUnauthorized.code:
                if not self.login():
                    return None
                LOG.info(_("Re-authenticated with CSR (%s)"), self.host)
                headers['X-auth-token'] = self.token
                r = requests.post(url, headers=headers, data=data,
                                  verify=False, timeout=self.timeout)
        except requests.Timeout as te:
            LOG.error(_("Timeout during POST for CSR (%(host)s): %(error)s"),
                      {'host': self.host, 'error': te})
            self.status = wexc.HTTPRequestTimeout.code
        except Exception as e:
            LOG.error(_("Unexpected error during POST for CSR (%(host)s): "
                        "%(error)s"),
                      {'host': self.host, 'error': e})
            self.status = wexc.HTTPInternalServerError.code
        else:
            self.status = r.status_code

    def put_request(self, resource, payload=None):
        """Perform a PUT request to a CSR resource.

        If this is the first time interacting with the CSR, a token will
        be obatained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more.
        """

        if not self.logged_in():
            if not self.login():
                return None

        url = 'https://%(host)s/api/v1/%(resource)s' % {'host': self.host,
                                                        'resource': resource}
        data = jsonutils.dumps(payload)
        headers = {'Accept': 'application/json',
                   'content-type': 'application/json',
                   'X-auth-token': self.token}
        # print "PUT request", url, headers, payload
        try:
            r = requests.put(url, headers=headers, data=data,
                             verify=False, timeout=self.timeout)
            if r.status_code == wexc.HTTPUnauthorized.code:
                if not self.login():
                    return None
                headers['X-auth-token'] = self.token
                r = requests.put(url, headers=headers, data=data,
                                 verify=False, timeout=self.timeout)
        except requests.Timeout as te:
            LOG.error(_("Timeout during PUT for CSR (%(host)s): "
                        "%(error)s"),
                      {'host': self.host, 'error': te})
            self.status = wexc.HTTPRequestTimeout.code
        except Exception as e:
            LOG.error(_("Unexpected error during put for CSR (%(host)s): "
                        "%(error)s"),
                      {'host': self.host, 'error': e})
            self.status = wexc.HTTPInternalServerError.code
        else:
            self.status = r.status_code

    def delete_request(self, resource):
        """Perform a DELETE request on a CSR resource.

        If this is the first time interacting with the CSR, a token will
        be obatained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more.
        """

        if not self.logged_in():
            if not self.login():
                return

        url = 'https://%(host)s/api/v1/%(resource)s' % {'host': self.host,
                                                        'resource': resource}
        headers = {'Accept': 'application/json',
                   'content-type': 'application/json',
                   'X-auth-token': self.token}
        # print "DELETE request", url, headers
        try:
            r = requests.delete(url, headers=headers,
                                verify=False, timeout=self.timeout)
            if r.status_code == wexc.HTTPUnauthorized.code:
                if not self.login():
                    return
                headers['X-auth-token'] = self.token
                r = requests.delete(url, headers=headers,
                                    verify=False, timeout=self.timeout)
        except requests.Timeout as te:
            LOG.error(_("Timeout during DELETE for CSR (%(host)s): "
                        "%(error)s"),
                      {'host': self.host, 'error': te})
            self.status = wexc.HTTPRequestTimeout.code
        except Exception as e:
            LOG.error(_("Unexpected error during DELETE for CSR (%(host)s): "
                        "%(error)s"),
                      {'host': self.host, 'error': e})
            self.status = wexc.HTTPInternalServerError.code
        else:
            self.status = r.status_code


if __name__ == '__main__':
    csr = Client('192.168.200.20', 'stack', 'cisco')

#     print "Start"
#     content = csr.get_request('global/host-name')
#     print "Status:", csr.status
#     print content
#     print "End"
#
#     print "Get token: ", csr.login()
#     print 'Token status %s, token=%s' %(csr.status, csr.token)
#
#     content = csr.get_request('global/host-name')
#     print "Get status %s, Content=%s" % (csr.status, content)
#
#     content = csr.get_request('global/local-users')
#     print "Get status %s, Content=%s" % (csr.status, content)
#
#     bad_host = Client('192.168.200.30', 'stack', 'cisco')
#     print "Get token: ", bad_host.login()
#     print 'Bad status %s' % bad_host.status

    content = csr.post_request('interfaces/gigabitEthernet0/statistics',
                               payload={'action': 'clear'})
    print "Good post status %s, Content=%s" % (csr.status, content)
    content = csr.post_request('no/such/request',
                               payload={'foo': 'bar'})
    print "Bad post status %s, Content=%s" % (csr.status, content)
