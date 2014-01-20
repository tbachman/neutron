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
# REMOVE import json

"""Mock REST requests to Cisco Cloud Services Router."""

import re

from functools import wraps
from httmock import urlmatch, all_requests, response
import requests
from webob import exc as wexc

from neutron.openstack.common import log as logging

# Temporary flags, until we get fixes sorted out.
FIXED_CSCul53598 = False
FIXED_CSCum10044 = False
V3_12_SUPPORT = False

LOG = logging.getLogger(__name__)
# TODO(pcm): Uncomment once bug is resolved.
# dumnmy_uuid = '1eb4ee6b-0870-45a0-b554-7b69096a809c'
dummy_uuid = '1eb4ee6b-0870-45a0-b554-7b69096'


def repeat(n):
    """Decorator to limit the number of times a handler is called.

    Will allow the wrapped function (handler) to be called 'n' times.
    After that, this will return None for any additional calls,
    allowing other handlers, if any, to be invoked.
    """

    class static:
        retries = n

    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if static.retries == 0:
                return None
            static.retries -= 1
            return func(*args, **kwargs)
        return wrapped
    return decorator


def filter(methods, resource):
    """Decorator to invoke handler once for a specific resource.

    This will call the handler only for a specific resource using
    a specific method(s). Any other resource request or method will
    return None, allowing other handlers, if any, to be invoked.
    """

    class static:
        target_methods = [m.upper() for m in methods]
        target_resource = resource

    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if (args[1].method in static.target_methods and
                static.target_resource in args[0].path):
                return func(*args, **kwargs)
            else:
                return None  # Not for this resource
        return wrapped
    return decorator


@urlmatch(netloc=r'localhost')
def token(url, request):
    if 'auth/token-services' in url.path:
        if FIXED_CSCul53598:
            return {'status_code': wexc.HTTPOk.code,
                    'content': {'token-id': 'dummy-token'}}
        else:
            return {'status_code': wexc.HTTPCreated.code,
                    'content': {'token-id': 'dummy-token'}}


@urlmatch(netloc=r'localhost')
def token_unauthorized(url, request):
    if 'auth/token-services' in url.path:
        return {'status_code': wexc.HTTPUnauthorized.code}


@urlmatch(netloc=r'wrong-host')
def token_wrong_host(url, request):
    raise requests.ConnectionError()


@all_requests
def token_timeout(url, request):
    raise requests.Timeout()


@filter(['get'], 'global/host-name')
@all_requests
def timeout(url, request):
    """Simulated timeout of a normal request."""

    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    raise requests.Timeout()


@urlmatch(netloc=r'localhost')
def no_such_resource(url, request):
    """Indicate not found error, when invalid resource requested."""
    if 'no/such/request' in url.path:
        return {'status_code': wexc.HTTPNotFound.code}


@filter(['get'], 'global/host-name')
@repeat(1)
@urlmatch(netloc=r'localhost')
def expired_request(url, request):
    """Simulate access denied failure on first request for this resource.

    Intent here is to simulate that the token has expired, by failing
    the first request to the resource. Because of the repeat=1, this
    will only be called once, and subsequent calls will not be handled
    by this function, but instead will access the normal handler and
    will pass. Currently configured for a GET request, but will work
    with POST and PUT as well. For DELETE, would need to filter on a
    different resource (e.g. 'global/local-users')
    """

    return {'status_code': wexc.HTTPUnauthorized.code}


@urlmatch(netloc=r'localhost')
def get(url, request):
    if request.method != 'GET':
        return
    LOG.debug("DEBUG: GET mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    if 'global/host-name' in url.path:
        content = {u'kind': u'object#host-name',
                   u'host-name': u'Router'}
        return response(wexc.HTTPOk.code, content=content)
    if 'global/local-users' in url.path:
        content = {u'kind': u'collection#local-user',
                   u'users': ['peter', 'paul', 'mary']}
        return response(wexc.HTTPOk.code, content=content)
    if 'interfaces/GigabitEthernet' in url.path:
        actual_interface = url.path.split('/')[-1]
        ip = actual_interface[-1]
        content = {u'kind': u'object#interface',
                   u'description': u'Nothing yet',
                   u'if-name': actual_interface,
                   u'proxy-arp': True,
                   u'subnet-mask': u'255.255.255.0',
                   u'icmp-unreachable': True,
                   u'nat-direction': u'',
                   u'icmp-redirects': True,
                   u'ip-address': u'192.168.200.%s' % ip,
                   u'verify-unicast-source': False,
                   u'type': u'ethernet'}
        return response(wexc.HTTPOk.code, content=content)
    if 'vpn-svc/ike/policies/2' in url.path:
        content = {u'kind': u'object#ike-policy',
                   u'priority-id': u'2',
                   u'version': u'v1',
                   u'local-auth-method': u'pre-share',
                   u'encryption': u'aes',
                   u'hash': u'sha',
                   u'dhGroup': 5,
                   u'lifetime': 3600}
        return response(wexc.HTTPOk.code, content=content)
    if 'vpn-svc/ike/keyrings' in url.path:
        content = {u'kind': u'object#ike-keyring',
                   u'keyring-name': u'5',
                   u'pre-shared-key-list': [
                       {u'key': u'super-secret',
                        u'encrypted': False,
                        u'peer-address': u'10.10.10.20 255.255.255.0'}
                   ]}
        return response(wexc.HTTPOk.code, content=content)
    if 'vpn-svc/ipsec/policies/' in url.path:
        ipsec_policy_id = url.path.split('/')[-1]
        content = {u'kind': u'object#ipsec-policy',
                   u'mode': u'tunnel',
                   # TODO(pcm): Use 'Disable', when fixed on CSR
                   u'anti-replay-window-size': u'128',
                   u'policy-id': u'%s' % ipsec_policy_id,
                   u'protection-suite': {
                       u'esp-encryption': u'esp-aes',
                       u'esp-authentication': u'esp-sha-hmac',
                       u'ah': u'ah-sha-hmac',
                   },
                   u'lifetime-sec': 120,
                   u'pfs': u'group5',
                   u'lifetime-kb': None,
                   u'idle-time': None}
        return response(wexc.HTTPOk.code, content=content)
    if 'vpn-svc/site-to-site/Tunnel' in url.path:
        tunnel = url.path.split('/')[-1]
        # Use same number, to allow mock to generate IPSec policy ID
        ipsec_policy_id = tunnel[6:]
        content = {u'kind': u'object#vpn-site-to-site',
                   u'vpn-interface-name': u'%s' % tunnel,
                   u'ip-version': u'ipv4',
                   u'vpn-type': u'site-to-site',
                   u'ipsec-policy-id': u'%s' % ipsec_policy_id,
                   u'local-device': {
                       u'ip-address': '10.3.0.1/24',
                       u'tunnel-ip-address': '10.10.10.10'
                   },
                   u'remote-device': {
                       u'tunnel-ip-address': '10.10.10.20'
                   }}
        if V3_12_SUPPORT:
            content.update({u'ike-profile-id': None,
                            u'mtu': 1500})
        return response(wexc.HTTPOk.code, content=content)
    if 'vpn-svc/ike/keepalive' in url.path:
        content = {u'interval': 60,
                   u'retry': 4,
                   u'periodic': True}
        return response(wexc.HTTPOk.code, content=content)
    if 'routing-svc/static-routes' in url.path:
        content = {u'destination-network': u'10.1.0.0/24',
                   u'kind': u'object#static-route',
                   u'next-hop-router': None,
                   u'outgoing-interface': u'GigabitEthernet1',
                   u'admin-distance': 1}
        return response(wexc.HTTPOk.code, content=content)


@filter(['get'], 'vpn-svc/ike/keyrings')
@urlmatch(netloc=r'localhost')
def get_fqdn(url, request):
    LOG.debug("DEBUG: GET FQDN mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    content = {u'kind': u'object#ike-keyring',
               u'keyring-name': u'5',
               u'pre-shared-key-list': [
                   {u'key': u'super-secret',
                    u'encrypted': False,
                    u'peer-address': u'cisco.com'}
               ]}
    return response(wexc.HTTPOk.code, content=content)


@filter(['get'], 'vpn-svc/ipsec/policies/')
@urlmatch(netloc=r'localhost')
def get_no_ah(url, request):
    LOG.debug("DEBUG: GET No AH mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    ipsec_policy_id = url.path.split('/')[-1]
    content = {u'kind': u'object#ipsec-policy',
               u'mode': u'tunnel',
               # TODO(pcm): Use 'Disable', when fixed on CSR
               u'anti-replay-window-size': u'128',
               u'policy-id': u'%s' % ipsec_policy_id,
               u'protection-suite': {
                   u'esp-encryption': u'esp-aes',
                   u'esp-authentication': u'esp-sha-hmac',
               },
               u'lifetime-sec': 120,
               u'pfs': u'group5',
               u'lifetime-kb': None,
               u'idle-time': None}
    return response(wexc.HTTPOk.code, content=content)


@urlmatch(netloc=r'localhost')
def get_defaults(url, request):
    if request.method != 'GET':
        return
    LOG.debug("DEBUG: GET mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    if 'vpn-svc/ike/policies/2' in url.path:
        content = {u'kind': u'object#ike-policy',
                   u'priority-id': u'2',
                   u'version': u'v1',
                   u'local-auth-method': u'pre-share',
                   u'encryption': u'des',
                   u'hash': u'sha',
                   u'dhGroup': 1,
                   u'lifetime': 86400}
        return response(wexc.HTTPOk.code, content=content)
    if 'vpn-svc/ipsec/policies/123' in url.path:
        content = {u'kind': u'object#ipsec-policy',
                   u'mode': u'tunnel',
                   u'anti-replay-window-size': u'64',
                   u'policy-id': u'123',
                   u'protection-suite': {},
                   u'lifetime-sec': None,
                   u'pfs': u'Disable',
                   u'lifetime-kb': None,
                   u'idle-time': None}
        return response(wexc.HTTPOk.code, content=content)


@filter(['get'], 'vpn-svc/site-to-site')
@urlmatch(netloc=r'localhost')
def get_unnumbered(url, request):
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    return response(wexc.HTTPServerError.code)
    # TODO(pcm): Once the bug is fixed on the CSR, remove the above line,
    # and uncomment the following lines...
#     tunnel = url.path.split('/')[-1]
#     content = {u'kind': u'object#vpn-site-to-site',
#                u'vpn-interface-name': u'%s' % tunnel,
#                u'ip-version': u'ipv4',
#                u'vpn-type': u'site-to-site',
#                u'ipsec-policy-id': u'123',
#                u'local-device': {
#                    u'ip-address': 'unnumbered GigabitEthernet3',
#                    u'tunnel-ip-address': '10.10.10.10'
#                },
#                u'remote-device': {
#                    u'tunnel-ip-address': '10.10.10.20'
#                }}
#     return response(wexc.HTTPOk.code, content=content)


@filter(['get'], 'vpn-svc/ike/keepalive')
@urlmatch(netloc=r'localhost')
def get_not_configured(url, request):
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    return {'status_code': wexc.HTTPNotFound.code}


@urlmatch(netloc=r'localhost')
def post(url, request):
    if request.method != 'POST':
        return
    LOG.debug("DEBUG: POST mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    if 'interfaces/GigabitEthernet' in url.path:
        return {'status_code': wexc.HTTPNoContent.code}
    if 'global/local-users' in url.path:
        if 'username' not in request.body:
            return {'status_code': wexc.HTTPBadRequest.code}
        if '"privilege": 20' in request.body:
            return {'status_code': wexc.HTTPBadRequest.code}
        headers = {'location': '%s/test-user' % url.geturl()}
        return response(wexc.HTTPCreated.code, headers=headers)
    if 'vpn-svc/ike/policies' in url.path:
        headers = {'location': "%s/2" % url.geturl()}
        return response(wexc.HTTPCreated.code, headers=headers)
    if 'vpn-svc/ipsec/policies' in url.path:
        m = re.search(r'"policy-id": "(\S+)"', request.body)
        if m:
            headers = {'location': "%s/%s" % (url.geturl(), m.group(1))}
            return response(wexc.HTTPCreated.code, headers=headers)
        return {'status_code': wexc.HTTPBadRequest.code}
    if 'vpn-svc/ike/keyrings' in url.path:
        headers = {'location': "%s/5" % url.geturl()}
        return response(wexc.HTTPCreated.code, headers=headers)
    if 'vpn-svc/site-to-site' in url.path:
        m = re.search(r'"vpn-interface-name": "(\S+)"', request.body)
        if m:
            headers = {'location': "%s/%s" % (url.geturl(), m.group(1))}
            return response(wexc.HTTPCreated.code, headers=headers)
        return {'status_code': wexc.HTTPBadRequest.code}
    if 'routing-svc/static-routes' in url.path:
        headers = {'location':
                   "%s/10.1.0.0_24_GigabitEthernet1" % url.geturl()}
        return response(wexc.HTTPCreated.code, headers=headers)


@filter(['post'], 'global/local-users')
@urlmatch(netloc=r'localhost')
def post_change_attempt(url, request):
    LOG.debug("DEBUG: POST change value mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    return {'status_code': wexc.HTTPNotFound.code,
            'content': {
                u'error-code': -1,
                u'error-message': u'user test-user already exists'}}


@urlmatch(netloc=r'localhost')
def post_duplicate(url, request):
    LOG.debug("DEBUG: POST duplicate mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    return {'status_code': wexc.HTTPBadRequest.code,
            'content': {
                u'error-code': -1,
                u'error-message': u'policy 2 exist, not allow to '
                                  u'update policy using POST method'}}


@filter(['post'], 'vpn-svc/site-to-site')
@urlmatch(netloc=r'localhost')
def post_missing_ipsec_policy(url, request):
    LOG.debug("DEBUG: POST missing ipsec policy mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    return {'status_code': wexc.HTTPBadRequest.code}


@filter(['post'], 'vpn-svc/site-to-site')
@urlmatch(netloc=r'localhost')
def post_missing_ike_policy(url, request):
    LOG.debug("DEBUG: POST missing ike policy mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    return {'status_code': wexc.HTTPBadRequest.code}


@filter(['post'], 'vpn-svc/site-to-site')
@urlmatch(netloc=r'localhost')
def post_bad_ip(url, request):
    LOG.debug("DEBUG: POST bad IP mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    # TODO(pcm): See if this is the right error
    return {'status_code': wexc.HTTPBadRequest.code}


@urlmatch(netloc=r'localhost')
def put(url, request):
    if request.method != 'PUT':
        return
    LOG.debug("DEBUG: PUT mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    # Any resource
    return {'status_code': wexc.HTTPNoContent.code}


@urlmatch(netloc=r'localhost')
def delete(url, request):
    if request.method != 'DELETE':
        return
    LOG.debug("DEBUG: DELETE mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    # Any resource
    return {'status_code': wexc.HTTPNoContent.code}


@urlmatch(netloc=r'localhost')
def delete_unknown(url, request):
    if request.method != 'DELETE':
        return
    LOG.debug("DEBUG: DELETE unknown mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    # Any resource
    return {'status_code': wexc.HTTPNotFound.code,
            'content': {
                u'error-code': -1,
                u'error-message': 'user unknown not found'}}


@urlmatch(netloc=r'localhost')
def delete_not_allowed(url, request):
    if request.method != 'DELETE':
        return
    LOG.debug("DEBUG: DELETE not allowed mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': wexc.HTTPUnauthorized.code}
    # Any resource
    return {'status_code': wexc.HTTPMethodNotAllowed.code}
