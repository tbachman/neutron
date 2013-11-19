import json
import requests
from webob import exc as wexc


class Client(object):

    """REST Client for accessing the Cisco Cloud Services Router."""

    """
    Try!!!
    s2 = requests.Session()
    s2.auth = ('stack', 'cisco')
    s2.post('https://192.168.200.20/api/v1/auth/token-services')
    s2.cert = None
    s2.post('https://192.168.200.20/api/v1/auth/token-services')
    s2.headers
    headers = {'content-type': 'application/json',
                       'Content-Length': '0',
                       'Accept': 'application/json'}
    s2.headers.update(headers)
    s2.post('https://192.168.200.20/api/v1/auth/token-services')
    s2.verify = None
    s2.post('https://192.168.200.20/api/v1/auth/token-services')
    """

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
        try:
            r = requests.post(url, headers=headers, timeout=self.timeout,
                              auth=self.auth, verify=False)
        except requests.ConnectionError as ce:
            # print "LOG: Unable to connect to CSR (%s): %s" % (self.host, ce)
            self.status = wexc.HTTPNotFound.code
        except requests.Timeout as te:
            # print "LOG: Timeout connecting to CSR (%s): %s" % (self.host, te)
            self.status = wexc.HTTPRequestTimeout.code
        else:
            self.status = r.status_code
            if self.status == wexc.HTTPCreated.code:
                self.token = r.json()['token-id']
                # print "LOG: Login successful. Token=", self.token
                return True

    def get_request(self, resource):
        """Perform a REST GET requests for a CSR resource.
        
        If this is the first time interacting with the CSR, a token will
        be obtained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more."""
        
        if not self.logged_in():
            if not self.login():
                return None
        
        url = 'https://%(host)s/api/v1/%(resource)s' % {'host': self.host,
                                                        'resource': resource}
        headers = {'Accept': 'application/json',
                   'X-auth-token': self.token}
        try:
            r = requests.get(url, headers=headers, 
                             verify=False, timeout=self.timeout)
            if r.status_code == wexc.HTTPUnauthorized.code:
                if not self.login():
                    # print "LOG: Unable to re-authenticate with CSR (%s)" % self.host
                    return None
                # print "LOG: Re-authenticated with CSR (%s)" % self.host
                headers['X-auth-token'] = self.token
                r = requests.get(url, headers=headers,
                                 verify=False, timeout=self.timeout)
        except requests.Timeout as te:
            # print "LOG: Timeout during get for CSR (%s): %s" % (self.host, te)
            self.status = wexc.HTTPRequestTimeout.code
        else:
            self.status = r.status_code
            if self.status == wexc.HTTPOk.code:
                return r.json()

    def post_request(self, resource, payload=None):
        """Perform a POST request to a CSR resource.
        
        If this is the first time interacting with the CSR, a token will
        be obatained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more."""
        
        if not self.logged_in():
            if not self.login():
                return None
        
        url = 'https://%(host)s/api/v1/%(resource)s' % {'host': self.host,
                                                        'resource': resource}
        data = json.dumps(payload)
        headers = {'Accept': 'application/json',
                   'content-type': 'application/json',
                   'X-auth-token': self.token}        
        print "POST request", url, headers, payload        
        try:
            r = requests.post(url, headers=headers, data=data,
                              verify=False, timeout=self.timeout)
            if r.status_code == wexc.HTTPUnauthorized.code:
                if not self.login():
                    # print "LOG: Unable to re-authenticate with CSR (%s)" % self.host
                    return None
                # print "LOG: Re-authenticated with CSR (%s)" % self.host
                headers['X-auth-token'] = self.token
                r = requests.post(url, headers=headers, data=data,
                                  verify=False, timeout=self.timeout)
        except requests.Timeout as te:
            # print "LOG: Timeout during post for CSR (%s): %s" % (self.host, te)
            self.status = wexc.HTTPRequestTimeout.code
        else:
            self.status = r.status_code
            if self.status == wexc.HTTPNotFound.code:
                print "Failed", r.json()

    def put_request(self, resource, payload=None):
        """Perform a PUT request to a CSR resource.
        
        If this is the first time interacting with the CSR, a token will
        be obatained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more."""

        if not self.logged_in():
            if not self.login():
                return None
        
        url = 'https://%(host)s/api/v1/%(resource)s' % {'host': self.host,
                                                        'resource': resource}
        data = json.dumps(payload)
        headers = {'Accept': 'application/json',
                   'content-type': 'application/json',
                   'X-auth-token': self.token}
        print "PUT request", payload      
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
            # print "LOG: Timeout during put for CSR (%s): %s" % (self.host, te)
            self.status = wexc.HTTPRequestTimeout.code
        else:
            self.status = r.status_code
            if r.content:
                print "PUT content", json.dumps(r.content)

    def delete_request(self, resource):
        """Perform a DELETE request on a CSR resource.
        
        If this is the first time interacting with the CSR, a token will
        be obatained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more."""

        if not self.logged_in():
            if not self.login():
                return None
        
        url = 'https://%(host)s/api/v1/%(resource)s' % {'host': self.host,
                                                        'resource': resource}
        headers = {'Accept': 'application/json',
                   'content-type': 'application/json',
                   'X-auth-token': self.token}
        print "DELETE request", url, headers        
        try:
            r = requests.delete(url, headers=headers,
                                verify=False, timeout=self.timeout)
            print "First try", r.content, r.status_code
            if r.status_code == wexc.HTTPUnauthorized.code:
                if not self.login():
                    return None
                headers['X-auth-token'] = self.token
                print 're-logged in and retry', url, headers
                r = requests.delete(url, headers=headers,
                                    verify=False, timeout=self.timeout)
        except requests.Timeout as te:
            # print "LOG: Timeout during delete for CSR (%s): %s" % (self.host, te)
            self.status = wexc.HTTPRequestTimeout.code
        except:
            print "LOG: Unexpected error during delete for CSR (%s): %s" % (self.host, te)
            self.status = wexc.HTTPInternalServerError.code
        else:
            self.status = r.status_code
            print "delete status", self.status


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

