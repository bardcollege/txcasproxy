

import sys
from .txcasproxy import ProxyApp
from .authinfo import AuthInfoApp
from twisted.application.service import Service
from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString
from twisted.web.server import Session, Site


class ProxyService(Service):
    def __init__(self, endpoint_s, proxied_url, cas_info, 
                    fqdn=None, authorities=None, plugins=None,
                    auth_info_resource=None, auth_info_endpoint_s=None,
                    excluded_resources=None, excluded_branches=None,
                    remote_user_header=None, logout_patterns=None, 
                    logout_passthrough=False,
                    template_dir=None, template_resource=None, 
                    session_length=900, debug=False, verbose=False,
                    proxy_client_endpoint_s=None, cas_client_endpoint_s=None): 
        session_length = int(session_length)
        self.port_s = endpoint_s
        self.auth_info_endpoint_s = auth_info_endpoint_s
        if endpoint_s.startswith("ssl:") or endpoint_s.startswith('tls:'):
            is_https = True
        else:
            is_https = False
        # Create the application. 
        cas_info = cas_info
        app = ProxyApp(
            proxied_url, 
            cas_info, 
            fqdn=fqdn, 
            authorities=authorities,
            plugins=plugins,
            is_https=is_https,
            excluded_resources=excluded_resources,
            excluded_branches=excluded_branches,
            remote_user_header=remote_user_header,
            logout_patterns=logout_patterns,
            logout_passthrough=logout_passthrough,
            template_dir=template_dir,
            template_resource=template_resource,
            proxy_client_endpoint_s=proxy_client_endpoint_s,
            cas_client_endpoint_s=cas_client_endpoint_s)
        app.verbose = verbose
        app.auth_info_resource = auth_info_resource
        root = app.app.resource()
        self.app = app
        self.site = Site(root)

        def sessionFactory(site, uid, reactor=None):
            s = Session(site, uid, reactor=reactor)
            s.sessionTimeout = session_length
            return s
        
        self.site.sessionFactory = sessionFactory
        self.site.displayTracebacks = debug
        self.listeningPorts = []

    def startService(self):
        if self.port_s is not None:
            endpoint = serverFromString(reactor, self.port_s)
            d = endpoint.listen(self.site)
            d.addCallback(self.register_port, 'app')
        if self.auth_info_endpoint_s is not None:
            authInfoApp = AuthInfoApp()
            self.authInfoApp = authInfoApp
            authInfoSite = Site(authInfoApp.app.resource())
            authInfoSite.displayTracebacks = self.site.displayTracebacks
            endpoint = serverFromString(reactor, self.auth_info_endpoint_s)
            d2 = endpoint.listen(authInfoSite)
            d2.addCallback(self.register_port, 'authInfoSite')
            
    def register_port(self, listeningPort, serviceName):
        self.listeningPorts.append(listeningPort)
        if serviceName == 'app':
            host = listeningPort.getHost()
            self.app.port = host.port
            self.app.handle_port_set()
        if serviceName == 'authInfoSite':
            self.app.authInfoCallback = self.authInfoApp.setAuthInfo

    def stopService(self):
        for listeningPort in self.listeningPorts:
            listeningPort.stopListening()

