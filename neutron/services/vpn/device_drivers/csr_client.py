import json
import requests
from webob import exc as wexc


class Client(object):

    """REST Client for accessing the Cisco Cloud Services Router."""

    def __init__(self, host, username, password, timeout=None):
        self.host = host
        self.auth = (username, password)
        self.token = None
        self.status = wexc.HTTPOk.code
        self.timeout = timeout

    def obtain_access_token(self):
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
                return True

    def get_request(self, resource):
        if not self.token:
            if not self.obtain_access_token():
                return None
        
        url = 'https://%(host)s/api/v1/%(resource)s' % {'host': self.host,
                                                        'resource': resource}
        headers = {'Accept': 'application/json',
                   'X-auth-token': self.token}

        # print "Headers", headers
        # print "URL", url
        try:
            r = requests.get(url, headers=headers, 
                             verify=False, timeout=self.timeout)
            if r.status_code == wexc.HTTPUnauthorized.code:
                if not self.obtain_access_token():
                    return None
                headers['X-auth-token'] = self.token
                r = requests.get(url, headers=headers,
                                 verify=False, timeout=self.timeout)
        except requests.Timeout as te:
            # print "LOG: Timeout during get for CSR (%s): %s" % (self.host, te)
            self.status = wexc.HTTPRequestTimeout.code
            return None
        self.status = r.status_code
        if self.status == wexc.HTTPOk.code:
            return r.json()

    def delete_request(self, resource):
        pass

if __name__ == '__main__':
    csr = Client('192.168.200.20', 'stack', 'cisco')

    print "Get token: ", csr.obtain_access_token()
    print 'Token status %s, token=%s' %(csr.status, csr.token)
    
    content = csr.get_request('global/host-name')
    print "Get status %s, Content=%s" % (csr.status, content)
    
    csr.delete_request('auth/token-services/')
    print "Delete status %s" % csr.status

    content = csr.get_request('global/local-users')
    print "Get status %s, Content=%s" % (csr.status, content)
     
    bad_host = Client('192.168.200.30', 'stack', 'cisco')
    print "Get token: ", bad_host.obtain_access_token()
    print 'Bad status %s' % bad_host.status

