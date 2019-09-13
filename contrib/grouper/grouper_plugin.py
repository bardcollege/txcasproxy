

#Standard library
import os.path
import shlex
import string
from textwrap import dedent
import urllib
from urllib import parse as urlparse

# Application modules
from txcasproxy.interfaces import IRProxyPluginFactory, IRProxyInfoAcceptor, \
                            IResponseContentModifier, ICASRedirectHandler, \
                            IResourceInterceptor, IStaticResourceProvider
from txcasproxy import proxyutils

# External modules
from jinja2 import Environment, FileSystemLoader
from jinja2.exceptions import TemplateNotFound
from twisted.internet import defer
from twisted.plugin import IPlugin
from zope.interface import implementer

@implementer(IPlugin, IRProxyPluginFactory)
class GrouperPluginFactory(object):
    """
    """

    tag = "grouper"

    opt_help = dedent('''\
            Plugin for reverse proxying Internet2 Grouper UI.
            ''')

    opt_usage = dedent('''\
        Options are supplied as a colon-separated key=value list.
        Valid options are:
        - cas_logout_url: The CAS service SSO logout URL.
        ''')

    def generatePlugin(self, argstring=""):
        """
        """
        settings = {}
        if argstring.strip() != "":
            parser = shlex.shlex(argstring, posix=True)
            parser.wordchars = string.printable
            parser.whitespace = ':'
            parser.commenters = ''
            parser.quotes = ''
            parser.escapedquotes = ''
            argdict = dict(tuple(token.split('=')) for token in parser)
            settings.update(argdict)
        return GrouperPlugin(**settings) 

@implementer(
    IRProxyInfoAcceptor, 
    IResponseContentModifier, 
    ICASRedirectHandler, 
    IResourceInterceptor,
    IStaticResourceProvider)
class GrouperPlugin(object):
    
    
    proxy_fqdn = None
    proxy_port = 443
    proxied_scheme = 'http'
    proxied_netloc = '127.0.0.1:8443'
    proxied_path = '/'
    expire_session = lambda self, uid: None
    
    mod_sequence = 7
    cas_redirect_sequence = 7
    interceptor_sequence = 7
    
    owasp_js_servlet_resource = '/grouper/grouperExternal/public/OwaspJavaScriptServlet'
    logout_resource = '/grouper/logout.do'
    cas_logout_url = None
    
    static_resource_base = "/_static/grouper"
    static_resource_dir = os.path.join(os.path.dirname(__file__), "static")
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    
    def __init__(self, **kwds):
        self.cas_logout_url = kwds.get('cas_logout_url', None)
        self._loader = FileSystemLoader(self.template_dir)
        self._env = Environment()
        
    def _renderTemplate(self, template_name, **kwds):
        """
        """
        env = self._env
        loader = self._loader
        try:
            templ = loader.load(env, template_name)
        except TemplateNotFound:
            raise ViewNotImplementedError("The template '%s' was not found." % template_name)
        return templ.render(**kwds).encode('utf-8')
        
    def handle_rproxy_info_set(self):
        proxied_netloc = self.proxied_netloc
        parts = proxied_netloc.split(":", 2)
        self.proxied_host = parts[0]
        
    def transform_content(self, content, request):
        """
        Transform `content`
        """
        if request.isSecure():
            scheme = 'https'
        else:
            scheme = 'http'
        p = urlparse.urlparse(request.uri)
        path = p.path
        params = p.params
        query = p.query
        fragment = p.fragment
        netloc = "%s:%d" % (self.proxy_fqdn, self.proxy_port)
        url = urlparse.urlunparse((scheme, netloc, path, params, query, fragment))
        proxied_url = proxyutils.proxy_url_to_proxied_url(
            self.proxied_scheme,
            self.proxy_fqdn, 
            self.proxy_port, 
            self.proxied_netloc, 
            self.proxied_path, 
            url)
        
        p = urlparse.urlparse(proxied_url)
        if p.path == self.owasp_js_servlet_resource:
            return defer.succeed(self.csrf_js_hack(content))
            
        return content
            
    def csrf_js_hack(self, s):
        """
        """
        s = s.replace(self.proxied_host, self.proxy_fqdn)
        s = s.replace('''part = "/grouper/" + url;''', '''part = "/" + url;''')
        s = s.replace(
            self.owasp_js_servlet_resource, 
            self.owasp_js_servlet_resource[len(self.proxied_path):])
        return s
        
    def intercept_service_url(self, service_url, request):
        """
        If there was an AJAX error, set the service URL to the login URL.
        """
        # Handle AJAX error failure CAS interception.
        p = urlparse.urlparse(service_url)
        params = urlparse.parse_qs(p.query)
        values = params.get('code', None)
        if values is not None and 'ajaxError' in values:
            p = urlparse.ParseResult(*tuple(p[:2] + ('/',) + p[3:4] + ('',) + p[5:]))
            url = urlparse.urlunparse(p)
            return url
        # Nothing to intercept.
        return defer.succeed(service_url)
        
    def should_resource_be_intercepted(self, url, method, headers, proxy_request):
        """
        Return True if resource should be intercepted.
        """
        p = urlparse.urlparse(url)
        if p.path == self.logout_resource:
            return True
        
    def handle_resource(self, url, method, headers, proxy_request):
        """
        Return a deferred that fires the response body or a response body.
        """
        p = urlparse.urlparse(url)
        assert self.should_resource_be_intercepted(url, method, headers, proxy_request), "Invalid resource: {method} {url}".format(method, url)
        
        if p.path == self.logout_resource:
            sess = proxy_request.getSession()
            self.expire_session(sess.uid)
            return self._renderTemplate(
                "logout.jinja2", 
                cas_logout_url=self.cas_logout_url, 
                static_path=self.static_resource_base)
        
def qsmap_to_qslist(qsmap):
    for k, v in qsmap.iteritems():
        for item in v:
            yield (k, item)

html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
    }

def html_escape(text):
    """Produce entities within text."""
    return "".join(html_escape_table.get(c,c) for c in text)

