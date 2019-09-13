

from OpenSSL import crypto
from twisted.internet import ssl, defer 
from twisted.internet.endpoints import clientFromString
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator
from twisted.python.components import proxyForInterface
from twisted.web.error import SchemeNotSupported
from twisted.web.iweb import IAgentEndpointFactory, IPolicyForHTTPS
from zope.interface import implementer

@implementer(IAgentEndpointFactory)
class WebClientEndpointFactory(object):
    """
    An Agent endpoint factory based on endpoint strings.
    """
    def __init__(self, reactor, endpoint_s):
        self.reactor = reactor
        self.endpoint_s = endpoint_s

    def endpointForURI(self, uri):
        return clientFromString(self.reactor, self.endpoint_s) 
