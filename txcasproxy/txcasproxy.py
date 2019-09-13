#! /usr/bin/env python

import http.cookies as Cookie
import http.cookiejar
import datetime
import json
import os.path
import socket
import sys
from urllib.parse import urlencode
from urllib import parse as urlparse
from .ca_trust import CustomPolicyForHTTPS
from .interfaces import (
        IAccessControl,
        IRProxyInfoAcceptor, 
        IResponseContentModifier,
        ICASRedirectHandler, IResourceInterceptor,
        IStaticResourceProvider)
from . import proxyutils
from .urls import does_url_match_pattern, parse_url_pattern
from .web_client import WebClientEndpointFactory
from .websocket_proxy import makeWebsocketProxyResource
from dateutil.parser import parse as parse_date
from jinja2 import Environment, FileSystemLoader
from jinja2.exceptions import TemplateNotFound
from klein import Klein
from OpenSSL import crypto
import treq
from treq.client import HTTPClient
from twisted.internet import defer, reactor
from twisted.internet.ssl import Certificate
from twisted.python import log
import twisted.web.client as twclient
from twisted.web.client import BrowserLikePolicyForHTTPS, Agent
from twisted.web.client import HTTPConnectionPool
from twisted.web.resource import Resource
from twisted.web.static import File
from lxml import etree


class ProxyApp(object):
    app = Klein()
    ns = "{http://www.yale.edu/tp/cas}"
    port = None
    logout_instant_skew = 5
    ticket_name = 'ticket'
    service_name = 'service'
    renew_name = 'renew'
    pgturl_name = 'pgtUrl'
    reactor = reactor
    auth_info_resource = None
    auth_info_callback = None
    remoteUserHeader = 'Remote-User'
    logout_patterns = None
    logout_passthrough = False
    verbose = False
    proxy_client_endpoint_s = None
    cas_client_endpoint_s = None
    
    def __init__(self, proxied_url, cas_info, 
            fqdn=None, authorities=None, plugins=None, is_https=True,
            excluded_resources=None, excluded_branches=None,
            remote_user_header=None, logout_patterns=None,
            logout_passthrough=False,
            template_dir=None, template_resource='/_templates',
            proxy_client_endpoint_s=None, cas_client_endpoint_s=None):
        self.proxy_client_endpoint_s = proxy_client_endpoint_s
        self.cas_client_endpoint_s = cas_client_endpoint_s
        self.logout_passthrough = logout_passthrough
        self.template_dir = template_dir
        if template_dir is not None:
            self.template_loader_ = FileSystemLoader(template_dir)
            self.template_env_ = Environment()
            self.templateStaticResource_ = self.create_template_static_resource()
        if template_resource is not None:
            if not template_resource.endswith('/'):
                template_resource = "{0}/".format(template_resource)
        if template_resource is not None and template_dir is not None:
            static_base = "{0}static/".format(template_resource)
            self.static = self.app.route(static_base, branch=True)(self.__class__.static)
            self.static_base = static_base
        self.template_resource = template_resource
        if logout_patterns is not None:
            self.logout_patterns = [parse_url_pattern(pattern) for pattern in logout_patterns]
        for pattern in self.logout_patterns:
            assert pattern is None or pattern.scheme == '', (
                "Logout pattern '{0}' must be a relative URL.".format(pattern))
        if remote_user_header is not None:
            self.remoteUserHeader = remote_user_header
        self.excluded_resources = excluded_resources
        self.excluded_branches = excluded_branches
        self.is_https = is_https
        if proxied_url.endswith('/'):
            proxied_url = proxied_url[:-1]
        self.proxied_url = proxied_url
        p = urlparse.urlparse(proxied_url)
        self.p = p
        self.proxied_scheme = p.scheme
        netloc = p.netloc
        self.proxied_netloc = netloc
        self.proxied_host = netloc.split(':')[0]
        self.proxied_path = p.path
        self.cas_info = cas_info
        cas_param_names = set([])
        cas_param_names.add(self.ticket_name.lower())
        cas_param_names.add(self.service_name.lower())
        cas_param_names.add(self.renew_name.lower())
        cas_param_names.add(self.pgturl_name.lower())
        self.cas_param_names = cas_param_names
        if fqdn is None:
            fqdn = socket.getfqdn()
        self.fqdn = fqdn
        self.valid_sessions = {}
        self.logout_tickets = {}
        self._make_agents(authorities)
        # Sort/tag plugins
        if plugins is None:
            plugins = []
        content_modifiers = []
        info_acceptors = []
        cas_redirect_handlers = []
        interceptors = []
        access_control = []
        for plugin in plugins:
            if IResponseContentModifier.providedBy(plugin):
                content_modifiers.append(plugin)
            if IRProxyInfoAcceptor.providedBy(plugin):
                info_acceptors.append(plugin)
            if ICASRedirectHandler.providedBy(plugin):
                cas_redirect_handlers.append(plugin)
            if IResourceInterceptor.providedBy(plugin):
                interceptors.append(plugin)
            if IAccessControl.providedBy(plugin):
                access_control.append(plugin)
        self.info_acceptors = info_acceptors
        content_modifiers.sort(key=lambda x: x.mod_sequence)
        self.content_modifiers = content_modifiers
        cas_redirect_handlers.sort(key=lambda x: x.cas_redirect_sequence)
        self.cas_redirect_handlers = cas_redirect_handlers
        interceptors.sort(key=lambda x: x.interceptor_sequence)
        self.interceptors = interceptors
        access_control.sort(key=lambda x: x.ac_sequence)
        self.access_control = access_control
        # Create static resources.
        static_resources = {}
        for plugin in plugins:
            if IStaticResourceProvider.providedBy(plugin):
                if plugin.static_resource_base in static_resources:
                    if static_resources[plugin.static_resource_base] != plugin.static_resource_dir:
                        raise Exception("Static resource conflict for '{0}': '{1}' != '{2}'".format(
                            plugin.static_resource_base,
                            static_resources[plugin.static_resource_base],
                            plugin.static_resource_dir))
                else:
                    static_resources[plugin.static_resource_base] = plugin.static_resource_dir
        self.static_handlers = []
        for n, (resource_base, resource_dir) in enumerate(static_resources.items()):
            handler = lambda self, request: File(resource_dir)
            handler = self.app.route(resource_base, branch=True)(handler)
            self.static_handlers.append(handler)

    def log(self, msg, important=False):
        if important or self.verbose:
            if important:
                tag = "INFO"
            else:
                tag = "DEBUG"
            log.msg("[{0}] {1}".format(tag, msg))

    def handle_port_set(self):
        fqdn = self.fqdn
        port = self.port
        proxied_scheme = self.proxied_scheme
        proxied_netloc = self.proxied_netloc
        proxied_path = self.proxied_path
        for plugin in self.info_acceptors:
            plugin.proxy_fqdn = fqdn
            plugin.proxy_port = port
            plugin.proxied_scheme = proxied_scheme
            plugin.proxied_netloc = proxied_netloc
            plugin.proxied_path = proxied_path
            plugin.handle_rproxy_info_set()
            plugin.expire_session = self._expired

    def _make_agents(self, auth_files):
        """
        Configure the web clients that:
        * perform backchannel CAS ticket validation
        * proxy the target site
        """
        self.connectionPool = HTTPConnectionPool(self.reactor)
        if auth_files is None or len(auth_files) == 0:
            agent = Agent(self.reactor, pool=self.connectionPool)
        else:
            extra_ca_certs = []
            for ca_cert in auth_files:
                with open(ca_cert, "rb") as f:
                    data = f.read()
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
                del data
                extra_ca_certs.append(cert)
            policy = CustomPolicyForHTTPS(extra_ca_certs)
            agent = Agent(self.reactor, contextFactory=policy, pool=self.connectionPool)
        if self.proxy_client_endpoint_s is not None:
            self.proxyConnectionPool = HTTPConnectionPool(self.reactor)
            self.proxy_agent = Agent.usingEndpointFactory(
                self.reactor,
                WebClientEndpointFactory(self.reactor, self.proxy_client_endpoint_s),
                pool=self.proxyConnectionPool)
        else:
            self.proxy_agent = agent
        if self.cas_client_endpoint_s is not None:
            self.casConnectionPool = HTTPConnectionPool(self.reactor)
            self.cas_agent = Agent.usingEndpointFactory(
                self.reactor,
                WebClientEndpointFactory(self.reactor, self.cas_client_endpoint_s),
                pool=self.casConnectionPool) 
        else:
            self.cas_agent = agent

    def is_excluded(self, request):
        resource = request.path
        if resource in self.excluded_resources:
            return True
        for excluded in self.excluded_branches:
            if proxyutils.is_resource_or_child(excluded, resource):
                return True
        return False

    def mod_headers(self, h):
        keymap = {}
        for k,v in h.items():
            key = k.lower()
            if key in keymap:
                keymap[key].append(k)
            else:
                keymap[key] = [k]
        if 'host' in keymap:
            for k in keymap['host']:
                h[k] = [self.proxied_netloc]
        if 'origin' in keymap:
            for k in keymap['origin']:
                h[k] = [self.proxied_netloc]
        if 'content-length' in keymap:
            for k in keymap['content-length']:
                del h[k]
        if 'referer' in keymap:
            referer_handled = False 
            keys = keymap['referer']
            if len(keys) == 1:
                k = keys[0]
                values = h[k]
                if len(values) == 1:
                    referer = values[0]
                    new_referer = self.proxy_url_to_proxied_url(referer)
                    if new_referer is not None:
                        h[k] = [new_referer]
                        self.log("Re-wrote Referer header: '%s' => '%s'" % (referer, new_referer))
                        referer_handled = True
            if not referer_handled:
                for k in keymap['referer']:
                    del h[k]
        return h

    def _check_for_logout(self, request):
        data = request.content.read()
        samlp_ns = "{urn:oasis:names:tc:SAML:2.0:protocol}"
        try:
            root = etree.fromstring(data)
        except Exception as ex:
            root = None
        if (root is not None) and (root.tag == "%sLogoutRequest" % samlp_ns):
            instant = root.get('IssueInstant')
            if instant is not None:
                try:
                    instant = parse_date(instant)
                except ValueError:
                    self.log("Invalid issue_instant supplied: '{0}'.".format(instant), important=True)
                    instant = None
                if instant is not None:
                    utcnow = datetime.datetime.utcnow()
                    seconds = abs((utcnow - instant.replace(tzinfo=None)).total_seconds())
                    if seconds <= self.logout_instant_skew:
                        results = root.findall("%sSessionIndex" % samlp_ns)
                        if len(results) == 1:
                            result = results[0]
                            ticket = result.text
                            sess_uid = self.logout_tickets.get(ticket, None)
                            if sess_uid is not None:
                                self._expired(sess_uid)
                                return True
                            else:
                                self.log(
                                    ("No matching session for logout request "
                                    "for ticket '{0}'.").format(ticket))
                    else:
                        self.log(
                            ("Issue instant was not within"
                            " {0} seconds of actual time.").format(
                                self.logout_instant_skew), important=True)
                else:
                    self.log("Could not parse issue instant.", important=True)
            else:
                self.log("'IssueInstant' attribute missing from root.", important=True)
        elif root is None:
            self.log("Could not parse XML.", important=True)
        return False

    @app.route("/", branch=True)
    def proxy(self, request):
        for pattern in self.logout_patterns:
            if does_url_match_pattern(request.uri, pattern):
                sess = request.getSession()
                sess_uid = sess.uid
                self._expired(sess_uid)
                cas_logout = self.cas_info.get('logout_url', None)
                if cas_logout is not None:
                    if self.logout_passthrough:
                        d = self.reverse_proxy(request, protected=False)
                    return request.redirect(cas_logout)
                else:
                    return self.reverse_proxy(request, protected=False)
        if self.is_excluded(request):
            return self.reverse_proxy(request, protected=False)
        valid_sessions = self.valid_sessions
        sess = request.getSession()
        sess_uid = sess.uid
        if not sess_uid in valid_sessions:
            self.log(
                ("Session {0} not in valid sessions.  "
                "Will authenticate with CAS.").format(sess_uid))
            if request.method == 'POST':
                headers = request.requestHeaders
                if headers.hasHeader("Content-Type"):
                    ct_list =  headers.getRawHeaders("Content-Type") 
                    #log.msg("[DEBUG] ct_list: %s" % str(ct_list))
                    for ct in ct_list:
                        if ct.find('text/xml') != -1 or ct.find('application/xml') != -1:
                            if self._check_for_logout(request):
                                return ""
                            else:
                                break
            # CAS Authentication
            # Does this request have a ticket?  I.e. is it coming back from a successful
            # CAS authentication?
            args = request.args
            ticket_name = self.ticket_name.encode()
            if ticket_name in args:
                values = args[ticket_name]
                if len(values) == 1:
                    ticket = values[0]
                    d = self.validate_ticket(ticket, request)
                    return d
            # If no ticket is present, redirect to CAS.
            d = self.redirect_to_cas_login(request)
            return d
        elif request.path == self.auth_info_resource:
            self.log("Providing authentication info.")
            return self.deliver_auth_info(request)
        else:
            d = self.reverse_proxy(request)
            return d

    def deliver_auth_info(self, request):
        valid_sessions = self.valid_sessions
        sess = request.getSession()    
        sess_uid = sess.uid
        session_info = valid_sessions[sess_uid]
        username = session_info['username']
        attributes = session_info['attributes']
        doc = {'username': username, 'attributes': attributes}
        serialized = json.dumps(doc)
        request.responseHeaders.setRawHeaders('Content-Type', ['application/json'])
        return serialized 
        
    def get_url(self, request):
        if self.is_https:
            scheme = 'https'
            default_port = 443
        else:
            scheme = 'http'
            default_port = 80
        fqdn = self.fqdn
        port = self.port
        if port is None:
            port = default_port
        if port == default_port:
            return urlparse.urljoin(f"{scheme}://{fqdn}", request.uri.decode())
        else:
            return urlparse.urljoin(f"{scheme}://{fqdn}:{port}",
                    request.uri.decode())
        
    def redirect_to_cas_login(self, request):
        """
        Begin the CAS redirection process.
        """        
        service_url = self.get_url(request)
        d = None
        for plugin in self.cas_redirect_handlers:
            if d is None:
                d = defer.maybeDeferred(plugin.intercept_service_url, service_url, request)
            else:
                d.addCallback(plugin.intercept_service_url, request)
        if d is None:
            return self.complete_redirect_to_cas_login(service_url, request)
        else:
            d.addCallback(self.complete_redirect_to_cas_login, request)
            return d
                
    def complete_redirect_to_cas_login(self, service_url, request):
        """
        Complete the CAS redirection process.
        Return a deferred that will redirect the user-agent to the CAS login.
        """
        cas_info = self.cas_info
        login_url = cas_info['login_url']
        p = urlparse.urlparse(login_url)
        params = {self.service_name: service_url}
        if p.query == '':
            param_str = urlencode(params)
        else:
            qs_map = urlparse.parse_qs(p.query)
            qs_map.update(params)
            param_str = urlencode(qs_map, doseq=True)
        p = urlparse.ParseResult(*tuple(p[:4] + (param_str,) + p[5:]))
        url = urlparse.urlunparse(p)
        self.log("Redirecting to CAS with URL '{0}'.".format(url))
        d = request.redirect(url)
        return d
        
    def validate_ticket(self, ticket, request):
        service_name = self.service_name
        ticket_name = self.ticket_name
        this_url = self.get_url(request)
        p = urlparse.urlparse(this_url)
        qs_map = urlparse.parse_qs(p.query)
        if ticket_name in qs_map:
            del qs_map[ticket_name]
        param_str = urlencode(qs_map, doseq=True)
        p = urlparse.ParseResult(*tuple(p[:4] + (param_str,) + p[5:]))
        service_url = urlparse.urlunparse(p)
        params = {
                service_name: service_url,
                ticket_name: ticket,}
        param_str = urlencode(params, doseq=True)
        p = urlparse.urlparse(self.cas_info['service_validate_url'])
        p = urlparse.ParseResult(*tuple(p[:4] + (param_str,) + p[5:]))
        service_validate_url = urlparse.urlunparse(p)
        self.log(
            "Requesting service-validate URL => '{0}' ...".format(
                service_validate_url))
        http_client = HTTPClient(self.cas_agent) 
        d = http_client.get(service_validate_url)
        d.addCallback(treq.content)
        d.addCallback(self.parse_sv_results, service_url, ticket, request)
        return d
        
    def parse_sv_results(self, payload, service_url, ticket, request):
        self.log("Parsing /serviceValidate results  ...")
        ns = self.ns
        try:
            root = etree.fromstring(payload)
        except (etree.XMLSyntaxError,) as ex:
            self.log((
                    "error='Error parsing XML payload.' "
                    "service='{0}' ticket={1}'/n{2}"
                    ).format(service_url, ticket, ex), important=True)
            return self.render_template_500(request)
        if root.tag != ('%sserviceResponse' % ns):
            self.log((
                    "error='Error parsing XML payload.  No `serviceResponse`.' "
                    "service='{0}' ticket={1}'"
                    ).format(service_url, ticket), important=True)
            return self.render_template_403(request)
        results = root.findall("{0}authenticationSuccess".format(ns))
        if len(results) != 1:
            self.log((
                    "error='Error parsing XML payload.  No `authenticationSuccess`.' "
                    "service='{0}' ticket={1}'"
                    ).format(service_url, ticket), important=True)
            return self.render_template_403(request)
        success = results[0]
        results = success.findall("{0}user".format(ns))
        if len(results) != 1:
            self.log((
                    "error='Error parsing XML payload.  Not exactly 1 `user`.' "
                    "service='{0}' ticket={1}'"
                    ).format(service_url, ticket), important=True)
            return self.render_template_403(request)
        user = results[0]
        username = user.text
        attributes = success.findall("{0}attributes".format(ns))
        attrib_map = {}
        for attrib_container in attributes:
            for elm in attrib_container.findall('./*'):
                tag_name = elm.tag[len(ns):]
                value = elm.text
                attrib_map.setdefault(tag_name, []).append(value)
        # Access control plugins
        access_control = self.access_control
        for ac_plugin in access_control:
            is_allowed, reason = ac_plugin.isAllowed(username, attrib_map)
            if not is_allowed:
                self.log((
                        "Access denied:  user='{username}' ac_plugin='{ac_plugin}' "
                        "reason={reason}, service='{service}' ticket='{ticket}'"
                        ).format(
                            username=username, 
                            ac_plugin=ac_plugin.tagname, 
                            service=service_url, 
                            ticket=ticket,
                            reason=reason), important=True)
                return self.render_template_403(request, username=username, reason=reason)
        # Update session session
        valid_sessions = self.valid_sessions
        logout_tickets = self.logout_tickets
        sess = request.getSession()
        sess_uid = sess.uid
        if sess_uid not in valid_sessions:
            valid_sessions[sess_uid] = {}
        valid_sessions[sess_uid].update({
            'username': username,
            'ticket': ticket,
            'attributes': attrib_map})
        if not ticket in logout_tickets:
            logout_tickets[ticket] = sess_uid
        auth_info_callback = self.auth_info_callback
        if auth_info_callback is not None: 
            auth_info_callback(username, attrib_map)
        sess.notifyOnExpire(lambda: self._expired(sess_uid))
        # Reverse proxy.
        return request.redirect(service_url)
        
    def _expired(self, uid):
        valid_sessions = self.valid_sessions
        if uid in valid_sessions:
            session_info = valid_sessions[uid]
            username = session_info['username']
            ticket = session_info['ticket']
            del valid_sessions[uid]
            auth_info_callback = self.auth_info_callback
            if auth_info_callback is not None:
                auth_info_callback(username, None)
            logout_tickets = self.logout_tickets
            if ticket in logout_tickets:
                del logout_tickets[ticket]
            self.log(
                ("label='Expired session.' session_id='{0}' "
                "username='{1}'").format(uid, username))
        
    def reverse_proxy(self, request, protected=True):
        if protected:
            sess = request.getSession()
            valid_sessions = self.valid_sessions
            sess_uid = sess.uid
            username = valid_sessions[sess_uid]['username']
        # Normal reverse proxying.
        kwds = {}
        cookiejar = {}
        kwds['allow_redirects'] = False
        kwds['cookies'] = cookiejar
        req_headers = self.mod_headers(dict(request.requestHeaders.getAllRawHeaders()))
        kwds['headers'] = req_headers
        if protected:
            kwds['headers'][self.remoteUserHeader] = [username]
        if request.method in ('PUT', 'POST'):
            kwds['data'] = request.content.read()
        url = self.proxied_url + request.uri
        # Determine if a plugin wants to intercept this URL.
        interceptors = self.interceptors
        for interceptor in interceptors:
            if interceptor.should_resource_be_intercepted(url, request.method, req_headers, request):
                return interceptor.handle_resource(url, request.method, req_headers, request)
        # Check if this is a request for a websocket.
        d = self.checkForWebsocketUpgrade(request)
        if d is not None:
            return d
        # Typical reverse proxying.    
        self.log("Proxying URL => {0}".format(url))
        http_client = HTTPClient(self.proxy_agent) 
        d = http_client.request(request.method, url, **kwds)

        def process_response(response, request):
            req_resp_headers = request.responseHeaders
            resp_code = response.code
            resp_headers = response.headers
            resp_header_map = dict(resp_headers.getAllRawHeaders())
            # Rewrite Location headers for redirects as required.
            if resp_code in (301, 302, 303, 307, 308) and "Location" in resp_header_map:
                values = resp_header_map["Location"]
                if len(values) == 1:
                    location = values[0]
                    if request.isSecure():
                        proxy_scheme = 'https'
                    else:
                        proxy_scheme = 'http'
                    new_location = self.proxied_url_to_proxy_url(proxy_scheme, location)
                    if new_location is not None:
                        resp_header_map['Location'] = [new_location]
            request.setResponseCode(response.code, message=response.phrase)
            for k,v in resp_header_map.items():
                if k == 'Set-Cookie':
                    v = self.mod_cookies(v)
                req_resp_headers.setRawHeaders(k, v)
            return response
            
        def mod_content(body, request):
            """
            Modify response content before returning it to the user agent.
            """
            d = None
            for content_modifier in self.content_modifiers:
                if d is None:
                    d = content_modifier.transform_content(body, request)
                else:
                    d.addCallback(content_modifier.transform_content, request)
            if d is None:
                return body
            else:
                return d
            
        d.addCallback(process_response, request)
        d.addCallback(treq.content)
        d.addCallback(mod_content, request)
        return d

    def checkForWebsocketUpgrade(self, request):
        
        def _extract(name):
            raw_value = request.getHeader(name)
            if raw_value is None:
                return set([])
            else:
                return set(raw_value.split(', '))

        upgrade = _extract("Upgrade")
        connection = _extract("Connection")
        if 'websocket' in upgrade and 'Upgrade' in connection:
            uri = request.uri
            proxy_fqdn = self.fqdn
            proxy_port = self.port
            proxied_scheme = self.proxied_scheme
            proxied_netloc = self.proxied_netloc
            proxied_path = self.proxied_path
            if self.is_https:
                scheme = 'wss'
            else:
                scheme = 'ws'
            netloc = "{0}:{1}".format(proxy_fqdn, proxy_port)
            proxy_url = "{0}://{1}{2}".format(scheme, netloc, request.uri)  
            if proxied_scheme == 'https':
                proxied_scheme = 'wss'
            else:
                proxied_scheme = 'ws'
            proxied_url = proxyutils.proxy_url_to_proxied_url(
                proxied_scheme, 
                proxy_fqdn, 
                proxy_port, 
                proxied_netloc, 
                proxied_path, 
                proxy_url,
            )
            origin = proxied_url
            kind = "tcp"
            if proxied_scheme == 'wss':
                kind = 'ssl'
            parts = proxied_netloc.split(":", 1)
            proxied_host = parts[0]
            if len(parts) == 2:
                proxied_port = int(parts[1])
            elif proxied_scheme == 'wss':
                proxied_port =  443
            else:
                proxied_port = 80
            extra = "" #TODO: SSL options.
            proxied_endpoint_str = "{0}:host={1}:port={2}{3}".format(
                kind,
                proxied_host,
                proxied_port,
                extra
            )
            if proxied_url is not None:
                resource = makeWebsocketProxyResource(
                    proxy_url, 
                    proxied_endpoint_str, 
                    proxied_url, 
                    request,
                    reactor=self.reactor, 
                    origin=origin,
                    verbose=self.verbose)
                return resource
        return None
    
    def mod_cookies(self, value_list):
        proxied_path = self.proxied_path
        proxied_path_size = len(proxied_path)
        results = []
        for cookie_value in value_list:
            c = Cookie.SimpleCookie()
            c.load(cookie_value)
            for k in list(c.keys()):
                m = c[k]
                if 'path' in m:
                    m_path = m['path']
                    if self.is_proxy_path_or_child(m_path):
                        m_path = m_path[proxied_path_size:]
                        m['path'] = m_path
            results.append(c.output(header='')[1:])
        return results
                     
    def is_proxy_path_or_child(self, path):
        return proxyutils.is_proxy_path_or_child(self.proxied_path, path)
    
    def proxied_url_to_proxy_url(self, proxy_scheme, target_url):
        return proxyutils.proxied_url_to_proxy_url(
            proxy_scheme,
            self.fqdn, 
            self.port, 
            self.proxied_netloc, 
            self.proxied_path, 
            target_url)
        
    def proxy_url_to_proxied_url(self, target_url):
        return proxyutils.proxy_url_to_proxied_url(
            self.proxied_scheme,
            self.fqdn, 
            self.port, 
            self.proxied_netloc,
            self.proxied_path,
            target_url)

    def get_template_static_base(self):
        if self.template_resource is None:
            return None
        else:
            return '{0}static/'.format(self.template_resource)

    def render_template_403(self, request, **kwargs):
        template_dir = self.template_dir
        if template_dir is None:
            request.setResponseCode(403)
            return ""
        else:
            return self.render_template('error/403.jinja2', request=request, **kwargs)

    def render_template_500(self, request, **kwargs):
        template_dir = self.template_dir
        if template_dir is None:
            request.setResponseCode(500)
            return ""
        else:
            return self.render_template('error/500.jinja2', request=request, **kwargs)

    def render_template(self, template_name, **kwargs):
        template_dir = self.template_dir
        try:
            template = self.template_loader_.load(self.template_env_, template_name)
        except TemplateNotFound:
            raise Exception("The template '{0}' was not found.".format(template_name))
        return template.render(static_base=self.static_base, **kwargs).encode('utf-8')
    
    def create_template_static_resource(self):
        static_path = os.path.join(self.template_dir, 'static')
        static = File(static_path)
        return static

    def static(self, request):
        return self.templateStaticResource_

    @app.handle_errors(Exception)
    def handle_uncaught_errors(self, request, failure):
        self.log("Uncaught exception: {0}".format(failure), important=True)
        return self.render_template_500(request=request, failure=failure)

