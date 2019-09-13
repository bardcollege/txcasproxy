
from urllib import parse as urlparse
from autobahn.twisted.resource import WebSocketResource
from autobahn.twisted.websocket import (
    WebSocketServerFactory,
    WebSocketServerProtocol,
    WebSocketClientFactory,
    WebSocketClientProtocol
)
from twisted.internet.endpoints import clientFromString
from twisted.python import log


class ProxiedWSClientProtocol(WebSocketClientProtocol):
    connectedToProxiedWS = False
    onMessageCallback = None
    onCloseCallback = None
    maxQueueSize = 100

    def __init__(self):
        WebSocketClientProtocol.__init__(self)
        self._queue = []

    def log(self, msg, important=False):
        if important or self.factory.verbose:
            if important:
                tag = "INFO"
            else:
                tag = "DEBUG"
            log.msg("[{0}] {1}".format(tag, msg))

    def onOpen(self):
        self.log("Connected to proxied websocket ({0}.".format(self.factory.url))
        self.connectedToProxiedWS = True
        self.log("Queue size={0}".format(len(self._queue)))
        for msg, isBinary in self._queue:
            self.sendMessage(msg, isBinary)
        self._queue = []

    def sendMessageToProxiedWS(self, msg, isBinary):
        if self.connectedToProxiedWS:
            if isBinary:
                self.log("sending binary msg: websocket='{0}'".format(
                    self.factory.url))
            else:
                self.log("sending: websocket='{0}' msg='{1}'".format(
                    self.factory.url, msg))
            self.sendMessage(msg.encode('utf8'), isBinary)
        else:
            q = self._queue
            if len(q) < self.maxQueueSize:
                q.append((msg.encode('utf8'), isBinary))
            else:
                raise Execption("Queue overflow error.")

    def onMessage(self, payload, isBinary):
        if isBinary:
            self.log("received binary msg: websocket='{0}'".format(
                self.factory.url))
        else:
            self.log("received: websocket='{0}' msg='{1}'".format(
                self.factory.url, payload))
        self.onMessageCallback(payload, isBinary)

    def onClose(self, wasClean, code, reason):
        self.log("proxied websocket ({0}) closed.".format(self.factory.url))
        self.onCloseCallback(wasClean, code, reason)


class ProxiedWSClientProtocolFactory(WebSocketClientFactory):
    protocol = ProxiedWSClientProtocol
    onMessage = None
    onClose = None
    verbose = False

    def buildProtocol(self, addr):
        proto = self.protocol()
        proto.onMessageCallback = self.onMessage
        proto.onCloseCallback = self.onClose
        proto.factory = self
        return proto


class WSProxyProtocol(WebSocketServerProtocol):
    debug = False
    reactor = None
    maxQueueSize = 100
    verbose = False
    _proxied_websocket = None

    def __init__(self, 
        ws_endpoint_str, 
        target_url, 
        origin=None, headers=None, verbose=False, reactor=None):
        """
        ws_endpoint_str: The proxied websocket endpoint string.
        target_url: should be a websocket URL, e.g. 'ws://127.0.0.1:9000'
        """
        WebSocketServerProtocol.__init__(self)
        self.verbose = verbose
        self.ws_endpoint_str = ws_endpoint_str
        self.target_url = target_url
        self.origin = origin
        self.headers = headers
        self._queue = []
        if self.reactor is None:
            from twisted.internet import reactor
            self.reactor = reactor

    def log(self, msg, important=False):
        if important or self.verbose:
            if important:
                tag = "INFO"
            else:
                tag = "DEBUG"
            log.msg("[{0}] {1}".format(tag, msg))

    def connectToProxiedWebsocket(self):
        wsfactory = ProxiedWSClientProtocolFactory(
            self.target_url, 
            origin=self.origin,
            headers=self.headers,
            debug=self.debug,
        )
        wsfactory.verbose = self.verbose
        wsfactory.onMessage = self.sendMessage
        wsfactory.onClose = self.handleClose
        e = clientFromString(self.reactor, self.ws_endpoint_str)
        d = e.connect(wsfactory)
        d.addCallback(self.handleConnected)
         
        def _eb(err):
            self.log(err, important=True)
            return err

        d.addErrback(_eb)

    def onConnect(self, r):
        self.log("Accepted connection to web socket (proxy for {0}).".format(self.target_url))
        self.connectToProxiedWebsocket()

    def handleConnected(self, proto):
        self.log("Connected to proxied websocket => {0}.".format(
            self.target_url))
        self._proxied_websocket = proto
        for payload, isBinary in self._queue:
            self.log("Sending queued message to proxied websocket ({0}).".format(
                self.target_url))
            proto.sendMessageToProxiedWS(payload, isBinary)
        self._queue = []
        
    def onMessage(self, payload, isBinary):
        self.log("Proxy websocket received message for {0}.".format(
            self.target_url))
        if not isBinary:
            self.log("websocket='{0}' message='{1}'".format(
                self.target_url, payload))
        if self._proxied_websocket is not None:
            self._proxied_websocket.sendMessageToProxiedWS(payload, isBinary)
        else:
            q = self._queue
            if len(q) < self.maxQueueSize:
                q.append((payload, isBinary))
            else:
                raise Exception("Queue overflow.")

    def handleClose(self, wasClean, code, reason):
        self.log("Proxied websocket ({0}) closed connection.  reason='{1}'".format(
            self.target_url, reason))
        self._proxied_websocket = None


def _strip_query(url):
    p = urlparse.urlparse(url)
    temp = list(p)
    temp[3] = ''
    temp[4] = ''
    temp[5] = ''
    temp = temp[:6]
    return urlparse.urlunparse(temp)

def makeWebsocketProxyResource(
        proxy_url, 
        proxied_ws_endpoint_str, 
        proxied_url, 
        request,
        origin=None, 
        reactor=None, 
        verbose=False):
    proxy_url = _strip_query(proxy_url)
    headers = dict((k, ' '.join(v)) for k, v in request.requestHeaders.getAllRawHeaders()
                if k in ['Cookie'])
    factory = WebSocketServerFactory(
        proxy_url,
        debug=False,
        debugCodePaths=False)
    factory.protocol = lambda : WSProxyProtocol(
        proxied_ws_endpoint_str, 
        proxied_url, 
        origin=origin,
        headers=headers,
        verbose=verbose,
        reactor=reactor,
    ) 
    resource = WebSocketResource(factory)
    return resource

