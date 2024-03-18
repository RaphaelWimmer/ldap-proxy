#! /usr/bin/env python3

"""
Simple rate-limiting LDAP proxy
Based on https://ldaptor.readthedocs.io/en/latest/cookbook/ldap-proxy.html
Limits the number of requests per minute that are sent to the upstream LDAP server.
No fancy sliding window, just a timer that resets the number of requests every minute and prints out the number of requests per minute

CC-0, Raphael Wimmer, 2024
"""

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldaperrors import LDAPTimeLimitExceeded
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer, protocol, reactor
from twisted.python import log
from twisted.python.logfile import DailyLogFile
from functools import partial
import sys
import threading
import time

PROTOCOL = "ssl"  # ssl or tcp
SERVER = "ldap.example.com"
SERVER_PORT = 636
LOCAL_PORT = 10636


class RateLimiter:

    REQUESTS_PER_MINUTE = 3

    def __init__(self):
        self.count = 0
        self.request_lock = threading.Lock()
        self.reset_thread = threading.Thread(target=self.reset_request_count)
        self.reset_thread.daemon = True
        self.reset_thread.start()

    def check(self, request):
        if type(request) is pureldap.LDAPUnbindRequest:
            return True # ignore unbind requests
        # else:
        with self.request_lock:
            self.count += 1
        if self.count > self.REQUESTS_PER_MINUTE:
            return False
        else:
            return True

    def reset_request_count(self):
        while True:
            time.sleep(60)
            with self.request_lock:
                log.msg(f'Requests per minute: {self.count}')
                self.count = 0


ratelimiter = RateLimiter()


class LoggingProxy(ProxyBase):

    def handleBeforeForwardRequest(self, request, controls, reply):
        global ratelimiter
        log.msg("Request => " + repr(request))
        if ratelimiter.check(request):
            return defer.succeed((request, controls))
        else:
            log.msg("> RATE LIMIT EXCEEDED")
            msg = pureldap.LDAPResult(resultCode=LDAPTimeLimitExceeded.resultCode, errorMessage="Rate Limit Exceeded")
            reply(msg)
            return defer.succeed(None)

    def handleProxiedResponse(self, response, request, controls):
        # log.msg("Request => " + repr(request))
        # log.msg("Response => " + repr(response))
        # log.msg("------------------------------------")
        log.msg(f"Response => ({len(repr(response))} bytes)")
        return defer.succeed(response)


def ldapBindRequestRepr(self):
    l = []
    l.append('version={0}'.format(self.version))
    l.append('dn={0}'.format(repr(self.dn)))
    l.append('auth=****')
    if self.tag != self.__class__.tag:
        l.append('tag={0}'.format(self.tag))
    l.append('sasl={0}'.format(repr(self.sasl)))
    return self.__class__.__name__+'('+', '.join(l)+')'


pureldap.LDAPBindRequest.__repr__ = ldapBindRequestRepr

if __name__ == '__main__':
    if len(sys.argv) > 1:
        LOCAL_PORT = int(sys.argv[1])
    log.startLogging(sys.stderr)
    # log.startLogging(DailyLogFile.fromFullPath("/var/log/ldapproxy.log"))
    factory = protocol.ServerFactory()
    proxiedEndpointStr = '{PROTOCOL}:host={SERVER}:port={SERVER_PORT}'
    use_tls = False
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)

    def buildProtocol():
        proto = LoggingProxy()
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto

    factory.protocol = buildProtocol
    reactor.listenTCP(LOCAL_PORT, factory)
    reactor.run()
