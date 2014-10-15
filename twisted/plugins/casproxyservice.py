
# Standard library
import sys

# Application modules
from txcasproxy.interfaces import IRProxyPluginFactory
from txcasproxy.service import ProxyService

# External modules
from twisted.application.service import IServiceMaker
from twisted.plugin import getPlugins, IPlugin
from twisted.python import usage
from zope.interface import implements


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
             formatString % (factory.tag, factory.opt_usage))
     stm.write('\n')

class Options(usage.Options):
    optFlags = [
            ["help-plugins", None, "Help about available plugins."],
        ]

    optParameters = [
                        ["endpoint", "e", None, "An endpoint connection string."],
                        ["proxied-url", "p", None, "The base URL to proxy."],
                        ["cas-login", "c", None, "The CAS /login URL."],
                        ["cas-service-validate", "s", None, "The CAS /serviceValidate URL."],
                        ["fqdn", None, None, "Explicitly specify the FQDN that should be included in URL callbacks."],
                    ]

    def __init__(self):
        usage.Options.__init__(self)
        self['authorities'] = []
        self['plugins'] = []
        self.valid_plugins = set([])
        for factory in getPlugins(IRProxyPluginFactory):
            if hasattr(factory, 'tag'):
                self.valid_plugins.add(factory.tag)

    def opt_addCA(self, pem_path):
        """
        Add a trusted CA public cert (PEM format).
        """
        self['authorities'].append(pem_path)
        
    def opt_plugin(self, name):
        """
        Include a plugin.
        """
        self['plugins'].append(name)

    def postOptions(self):
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
        bad_tags = [tag for tag in self['plugins'] if tag not in self.valid_plugins]
        if len(bad_tags) > 0:
            bad_tags.sort()
            msg = "The following plugins are not valid: %s." % (', '.join(bad_tags))
            raise usage.UsageError(msg)

class MyServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "casproxy"
    description = "CAS Authenticating Proxy"
    options = Options

    def makeService(self, options):
        """
        """
        factories = [f for f in getPlugins(IRProxyPluginFactory) 
                        if hasattr(f, 'tag') and hasattr(f, 'opt_usage')]
        if options['help-plugins']:
            format_plugin_help_list(factories, sys.stderr)
            sys.exit(0)
            
        cas_info = dict(
            login_url=options['cas-login'],
            service_validate_url=options['cas-service-validate'])
        fqdn = options.get('fqdn', None)
        
        # Load plugins.
        plugin_opts = {}
        for plugin_arg in options['plugins']:
            parts = plugin_arg.split(':', 2)
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
        
        # Create the service.
        return ProxyService(
            endpoint_s=options['endpoint'], 
            proxied_url=options['proxied-url'],
            cas_info=cas_info,
            fqdn=fqdn,
            authorities=options['authorities'],
            plugins=plugins) 

# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = MyServiceMaker()

