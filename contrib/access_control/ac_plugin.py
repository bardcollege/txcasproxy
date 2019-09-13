
import shlex
import string
from textwrap import dedent
from txcasproxy.interfaces import (
    IRProxyPluginFactory, 
    IAccessControl)
from txcasproxy import proxyutils
from jinja2 import Environment, FileSystemLoader
from jinja2.exceptions import TemplateNotFound
from twisted.internet import defer
from twisted.plugin import IPlugin
from yaml import load
from zope.interface import implementer

@implementer(IPlugin, IRProxyPluginFactory)
class AccessControlPluginFactory(object):
    tag = "access_control"
    opt_help = dedent('''\
        Plugin for enforcing simple access control based on CAS attributes.
        ''')
    opt_usage = dedent('''\
        Options are supplied as a colon-separated key=value list.
        Valid options are:
        - config: Path to an access control config file.
        ''')

    def generatePlugin(self, argstring=""):
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
        plugin = AccessControlPlugin()
        plugin.config = settings.get('config', None)
        return plugin

@implementer(IAccessControl)
class AccessControlPlugin(object):
    tagname = "access_control" 
    ac_sequence = 1
    config = None
    _rules = None

    def _lazyLoadConfig(self):
        if self._rules is None:
            config = self.config
            if not config is None:
                with open(config, "r") as f:
                    self._rules = load(f)
        return self._rules

    @property
    def rules(self):
        return self._lazyLoadConfig()

    def isAllowed(self, username, attrib_map):
        """
        Returns (is_allowed, reason)
        If `is_allowed` is True, `reason` should be None.
        `reason` should be suitable for display to an end user
        """
        rules = self.rules
        if rules is None:
            return True
        for attrib, info in rules.iteritems():
            if not attrib in attrib_map:
                msg = "Missing attribute `{0}`.".format(attrib)
                return False, msg        
            if info is None:
                continue
            if 'allowed_values' in info:
                allowed_values = set(info['allowed_values'])
                attrib_values = attrib_map[attrib]
                match_found = False
                for attrib_value in attrib_values:
                    if attrib_value in allowed_values:
                        match_found = True
                        break
                if not match_found:
                    msg = "Attribute '{0}' value '{1}' not in allowed values.".format(
                        attrib,
                        attrib_value)
                    return False, msg
        return True, None
