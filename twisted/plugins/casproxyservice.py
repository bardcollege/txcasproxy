
# Standard library
from __future__ import print_function
import sys
# Application modules
from txcasproxy.interfaces import IRProxyPluginFactory
from txcasproxy.service import ProxyService
# External modules
from twisted.application.service import IServiceMaker
from twisted.plugin import getPlugins, IPlugin
from twisted.python import usage
from zope.interface import implementer


def format_plugin_help_list(factories, stm):
     """
     Show plugin list with brief usage..
     """
     # Figure out the right width for our columns
     firstLength = 0
     for factory in factories:
         if len(factory.tag) > firstLength:
             firstLength = len(factory.tag)
     formatString = '  %%-%is\t%%s\n' % firstLength
     stm.write(formatString % ('Plugin', 'ArgString format'))
     stm.write(formatString % ('======', '================'))
     for factory in factories:
         stm.write(
             formatString % (factory.tag, factory.opt_help))
     stm.write('\n')

def get_tag(plugin_str):
    """
    Get the tag from a plugin string.
    """
    parts = plugin_str.split(':', 1)
    return parts[0]

class Options(usage.Options):
    optFlags = [
            ["help-plugins", None, "Help about available plugins."],
            ["debug", 'd', "Errors served as HTML."],
            ["verbose", 'v', "Verbose logging."],
            ["logout-passthrough", None, "Pass the logout request through to backend service prior to intercepting and redirecting."],
        ]

    optParameters = [
                        ["endpoint", "e", None, "An endpoint connection string."],
                        ["proxied-url", "p", None, "The base URL to proxy."],
                        ["cas-login", "c", None, "The CAS /login URL."],
                        ["cas-service-validate", "s", None, "The CAS /serviceValidate URL."],
                        ["cas-logout", "l", None, "The CAS /logout URL.  Requires `logout` option to be set."],
                        ["header", "H", "REMOTE_USER", "The name of the header in which to pass the authenticated user ID."],
                        ["fqdn", None, None, 
                            "Explicitly specify the FQDN that should be included in URL callbacks."],
                        ["auth-info-endpoint", "a", None, "Endpoint for the authentication info service."],
                        ["auth-info-resource", "A", None, 
                            "Resource on the main site that provides authentication info."],
                        ["help-plugin", None, None, "Help or a specific plugin."],
                        ["template-dir", "t", None, "Folder containing templates."],
                        ["template-resource", "T", "/_templates", "Base resource for templates."],
                        ["session-length", "S", 900, "Session length in seconds."],
                        ["proxy-client-endpoint", "P", None, "An endpoint connection string for the proxy web client."],
                        ["cas-client-endpoint", "C", None, "An endpoint connection string for the back channel CAS web client."],
                    ]

    def __init__(self):
        usage.Options.__init__(self)
        self['authorities'] = []
        self['logouts'] = []
        self['plugins'] = []
        self.valid_plugins = set([])
        self['excluded-resources'] = set([])
        self['excluded-branches'] = set([])
        for factory in getPlugins(IRProxyPluginFactory):
            if hasattr(factory, 'tag'):
                self.valid_plugins.add(factory.tag)

    def opt_addCA(self, pem_path):
        """
        Add a trusted CA public cert (PEM format).
        """
        self['authorities'].append(pem_path)
        
    def opt_logout(self, logout_pattern):
        """
        Add a logout resource pattern to intercept and terminate the proxy session.
        """
        self['logouts'].append(logout_pattern)

    opt_L = opt_logout

    def opt_plugin(self, name):
        """
        Include a plugin.
        """
        self['plugins'].append(name)

    def opt_exclude(self, resource):
        """
        Exclude a specific resource from being proxied.
        """
        self['excluded-resources'].add(resource)

    def opt_excludeBranch(self, branch):
        """
        Exclude a resource and all its children from being proxied
        """
        self['excluded-branches'].add(branch)

    def postOptions(self):
        if self['help-plugins'] or self['help-plugin'] is not None:
            return
        if self['endpoint'] is None:
            raise usage.UsageError("Must specify a connection endpoint.")
        if self['proxied-url'] is None:
            raise usage.UsageError("Must specify base URL to proxy.")
        if self['cas-login'] is None:
            raise usage.UsageError("Must specify CAS login URL.")
        if self['cas-service-validate'] is None:
            login = self['cas-login']
            parts = login.split('/')
            parts[-1] = "serviceValidate"
            serviceValidate = '/'.join(parts)
            self['cas-service-validate'] = serviceValidate
            del parts
            del login
        bad_tags = [get_tag(plugin_str) for plugin_str in self['plugins'] 
                        if get_tag(plugin_str) not in self.valid_plugins]
        if len(bad_tags) > 0:
            bad_tags.sort()
            msg = "The following plugins are not valid: {0}.".format(
                ', '.join(bad_tags))
            raise usage.UsageError(msg)


@implementer(IServiceMaker, IPlugin)
class MyServiceMaker(object):
    tapname = "casproxy"
    description = "CAS Authenticating Proxy"
    options = Options

    def makeService(self, options):
        factories = [f for f in getPlugins(IRProxyPluginFactory) 
                        if hasattr(f, 'tag') and hasattr(f, 'opt_help') and hasattr(f, 'opt_usage')]
        if options['help-plugins']:
            format_plugin_help_list(factories, sys.stderr)
            sys.exit(0)
        help_plugin = options.get('help-plugin', None)
        if help_plugin is not None:
            for factory in factories:
                if factory.tag == help_plugin:
                    sys.stdout.write(factory.opt_usage)
                    sys.stdout.write('\n')
                    sys.exit(0)
            sys.stderr.write("No such plugin, '{0}'.\n".format(help_plugin))
            sys.exit(0)
        cas_info = dict(
            login_url=options['cas-login'],
            service_validate_url=options['cas-service-validate'],
            logout_url=options['cas-logout'])
        fqdn = options.get('fqdn', None)
        # Load plugins.
        plugin_opts = {}
        for plugin_arg in options['plugins']:
            parts = plugin_arg.split(':', 1)
            name = parts[0]
            if len(parts) > 1:
                args = parts[1]
            else:
                args = ''
            plugin_opts.setdefault(name, []).append(args)
        plugins = []
        for factory in factories:
            tag = factory.tag
            if tag in plugin_opts:
                arglst = plugin_opts[tag]
                for argstr in arglst:
                    plugin = factory.generatePlugin(argstr)
                    plugins.append(plugin)
        auth_info_endpoint_s = options['auth-info-endpoint']
        auth_info_resource = options['auth-info-resource'] 
        excluded_resources = options['excluded-resources']
        excluded_branches = options['excluded-branches']
        logouts = options['logouts']
        cas_logout = options['cas-logout']
        if cas_logout is not None and len(logouts) == 0:
            print("Option `logout` required for option `cas-logout`.", file=sys.stderr)
            sys.exit(1)
        # Create the service.
        return ProxyService(
            endpoint_s=options['endpoint'], 
            proxied_url=options['proxied-url'],
            cas_info=cas_info,
            fqdn=fqdn,
            authorities=options['authorities'],
            plugins=plugins,
            auth_info_endpoint_s=auth_info_endpoint_s,
            auth_info_resource=auth_info_resource,
            excluded_resources=excluded_resources,
            excluded_branches=excluded_branches,
            remote_user_header=options['header'],
            logout_patterns=logouts,
            logout_passthrough=options['logout-passthrough'],
            template_dir=options['template-dir'],
            template_resource=options['template-resource'],
            debug=options['debug'],
            verbose=options['verbose'],
            session_length=options['session-length'],
            proxy_client_endpoint_s=options['proxy-client-endpoint'],
            cas_client_endpoint_s=options['cas-client-endpoint'])


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.
serviceMaker = MyServiceMaker()

