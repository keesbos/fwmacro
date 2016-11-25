#!/usr/bin/env python
#
# Copyright (c) 2010, ZX. All rights reserved.
# Copyright (c) 2016, Capitar. All rights reserved.
#
# Released under the MIT license. See LICENSE file for details.
#

import netaddr
import netifaces
import socket
import os
import os.path
import re
import sys
import subprocess
import time


__version__ = (2, 9, 6)


class FWMacroException(Exception):
    """Base exception for fwmacro"""
    pass


class FWSyntaxError(FWMacroException):
    """Basic syntax error"""

    def __init__(self, lineno, msg):
        self.lineno = lineno
        self.msg = msg

    def __str__(self):
        return "{} at line {}".format(self.msg, self.lineno)


class FWUndefinedError(FWMacroException):
    """Undefined name"""

    def __init__(self, lineno, name, entity=None):
        self.lineno = lineno
        self.name = name
        self.entity = entity

    def __str__(self):
        entity = "{}".format(self.entity) if self.entity else ""
        return "Undefined {} {} at line {}".format(
            entity, self.name, self.lineno)


class FWRedefinitionError(FWMacroException):
    """Redefinition detected"""

    def __init__(self, lineno, name, entity=None, reflineno=None):
        self.lineno = lineno
        self.name = name
        self.entity = entity
        self.reflineno = reflineno

    def __str__(self):
        entity = " {}".format(self.entity) if self.entity else ""
        if self.reflineno:
            refline = " (defined at line {})".format(self.reflineno)
        else:
            refline = ""
        return "Redefinition of {}{} at line {}{}".format(
            entity, self.name, self.lineno, refline)


class FWRecursionError(FWMacroException):
    """Recursion detected in resolving names"""

    def __init__(self, lineno, name, *groups):
        self.lineno = lineno
        self.name = name
        self.groups = groups

    def __str__(self):
        groups = list(self.args)
        lines = []
        for group in groups:
            lines.append("{}: {}".format(group.name, group.lineno))
        return (
            "Recursion detected in group definition for group {}: {}"
        ).format(self.name, ", ".join(lines))


class FWResolveError(FWMacroException):
    """Resolve error for hostnames"""

    def __init__(self, lineno, name, msg):
        self.lineno = lineno
        self.name = name
        self.msg = msg

    def __str__(self):
        msg = ": {}".format(self.msg) if self.msg else ""
        return "Cannot resolve {}{}".format(self.name, msg)


class FWIPMaskBoundaryError(FWMacroException):
    """IP not on lower mask boundary"""

    def __init__(self, lineno, ip):
        self.lineno = lineno
        self.ip = ip

    def __str__(self):
        return "IP is not on mask boundary ({}) at line {}".format(
            self.ip, self.lineno)


class FWInvalidTable(FWMacroException):
    """Invalid table name"""

    def __init__(self, lineno, name):
        self.lineno = lineno
        self.name = name

    def __str__(self):
        return "Invalid table name {}".format(self.name)


class FWInvalidParentChain(FWMacroException):
    """Invalid parent chain"""

    def __init__(self, lineno, table, chain):
        self.lineno = lineno
        self.table = table
        self.chain = chain

    def __str__(self):
        return "Invalid parent chain {} in table {}".format(
            self.chain,
            self.table,
        )


class FWReservedChainName(FWMacroException):
    """Reserved name used or a chain definition"""

    def __init__(self, lineno, fname, chain):
        self.lineno = lineno
        self.fname = fname
        self.chain = chain

    def __str__(self):
        return "Reserved chain name {} at {}:{}".format(
            self.chain,
            self.fname,
            self.lineno,
        )


class FWOrderConflict(FWMacroException):

    def __init__(self, lineno, fname, chain, origdef):
        self.lineno = lineno
        self.fname = fname
        self.chain = chain
        self.origdef = origdef

    def __str__(self):
        return (
            "Order redefinition of chain {} at {}:{} "
            "(first defined at {}:{})"
        ).format(
            self.chain,
            self.fname,
            self.lineno,
            self.origdef[1],
            self.origdef[2],
        )


class FWIndentError(FWMacroException):

    def __init__(self, lineno, direction):
        self.lineno = lineno
        assert direction in [None, '-', '+']
        self.direction = direction

    def __str__(self):
        if self.direction == '-':
            msg = "Dedent error at line {}"
        elif self.direction == '+':
            msg = "Indent error at line {}"
        else:
            msg = "Indentation error at line {}"
        return msg.format(self.lineno)


class FWInvalidName(FWMacroException):

    def __init__(self, lineno, name):
        self.lineno = lineno
        self.name = name

    def __str__(self):
        return "Invalid name {} at line {}".format(self.name, self.lineno)


class FWInvalidIP(FWMacroException):

    def __init__(self, lineno, address):
        self.lineno = lineno
        self.address = address

    def __str__(self):
        return "Invalid IP address {} at line {}".format(
            self.address, self.lineno)


class FWInvalidPort(FWMacroException):

    def __init__(self, lineno, port):
        self.lineno = lineno
        self.port = port

    def __str__(self):
        return "Invalid port {} at line {}".format(
            self.port, self.lineno)


class FWExpectedError(FWMacroException):

    def __init__(self, lineno, text, expected=None):
        self.lineno = lineno
        self.text = text
        self.expected = expected

    def __str__(self):
        if not self.expected:
            return "Unexpected {} at line {}".format(self.text, self.lineno)
        if isinstance(self.expected, str):
            expected = self.expected
        elif len(self.expected) == 1:
            expected = self.expected
        else:
            expected = "one of {}".format(", ".join([
                i for i in self.expected if i is not None]))
        return "Expected {} but got {} at line {}".format(
            expected, self.text, self.lineno)


class FWGroupNameRequired(FWMacroException):

    def __init__(self, lineno, text):
        self.lineno = lineno
        self.text = text

    def __str__(self):
        return "Group names are required. Got {} at line {}".format(
            self.text, self.lineno)


class Chain(object):

    def __init__(self, lineno, name, condition=None):
        self.lineno = lineno
        self.name = name
        self.condition = condition

    def __str__(self):
        return "line: {}, name: {}, condition: {}".format(
            self.lineno, self.local, self.direction, self.action,
        )

    def __repr__(self):
        return "<Chain {}>".format(self.__str__())


class Rule(object):
    """Represention of a input (FWPreprocess) rule"""

    def __init__(self, lineno, local, direction, chainname=None):
        self.lineno = lineno
        self.local = local
        self.direction = direction
        self.action = None
        self.protocol = None
        self.icmp4 = []
        self.icmp6 = []
        self.state = "NEW"
        self.tcpflags = []
        self.sources = []
        self.srcports = []
        self.destinations = []
        self.dstports = []
        self.logging = ""
        self.logname = ""
        self.nat = ""
        self.natports = ""
        self._chainname = chainname

    def __str__(self):
        return "line: {}, local: {}, direction: {}, action: {}".format(
            self.lineno, self.local, self.direction, self.action,
        )

    def __repr__(self):
        return "<Rule {}>".format(self.__str__())

    def chainname(self, chainnr, chainname, iface):
        if self._chainname:
            return self._chainname
        if self.local:
            direction_char = self.direction[0].upper()
        else:
            direction_char = self.direction[0].lower()
        chainname = "{}{}:{}".format(direction_char, iface, chainname)
        if len(chainname) >= 30:
            chainname = "{}{}:{}{}".format(
                iface, direction_char, chainnr, chainname)
            chainname = chainname[:29]
        # self._chainname = chainname
        return chainname


class Token(object):

    def __init__(self, lineno, indent, text, quote=None):
        self.lineno = lineno
        self.indent = indent
        self.text = text
        self.quote = quote

    def __str__(self):
        return "{}:{}:{}".format(self.lineno, self.indent, self.text)

    def __repr__(self):
        return "Token({}, {}, {})".format(
            self.lineno, self.indent, self.text)


class Group(list):
    """Group object containing groups/hostnames/ips"""

    cached = {}

    def __init__(self, name, lineno):
        self.name = name
        self.lineno = lineno
        self.resolved = None
        self.ipv4 = []
        self.ipv6 = []
        self.referred_lines = []

    def resolve(self):
        if self.name not in self.cached:
            self.cached[self.name] = self
        if self.resolved is False:
            raise FWRecursionError(self.lineno, self.name, [self])
        if self.resolved is None:
            self.resolved = False
            for obj in self:
                ipv4, ipv6 = [], []
                if isinstance(obj, Group):
                    try:
                        ipv4, ipv6 = obj.resolve()
                    except FWRecursionError as e:
                        raise FWRecursionError(
                            self.lineno, self.name, e.groups + [self])
                else:
                    assert isinstance(obj, netaddr.IPNetwork), obj
                    if obj.version == 4:
                        ipv4 = [obj]
                    else:
                        ipv6 = [obj]
                for ip in ipv4:
                    if ip not in self.ipv4:
                        if (
                            isinstance(ip, netaddr.IPNetwork) and
                            ip.network != ip.ip
                        ):
                            raise FWIPMaskBoundaryError(ip, self.lineno)
                        self.ipv4.append(ip)
                for ip in ipv6:
                    if ip not in self.ipv6:
                        if (
                            isinstance(ip, netaddr.IPNetwork) and
                            ip.network != ip.ip
                        ):
                            raise FWIPMaskBoundaryError(ip, self.lineno)
                        self.ipv6.append(ip)
        self.resolved = True
        self.ipv4.sort()
        self.ipv6.sort()
        return self.ipv4, self.ipv6

    def ips(self):
        assert self.resolved is not None
        return self.ipv4 + self.ipv6


class Hostname(Group):

    def resolve(self):
        if self.name not in self.cached:
            self.cached[self.name] = self
        if self.resolved is None:
            self.resolved = False
            try:
                ainfos = socket.getaddrinfo(self.name, None)
            except socket.gaierror as why:
                raise FWResolveError(self.name, why[1], self.lineno)
            except:
                raise FWResolveError(self.name, None, self.lineno)
            for ainfo in ainfos:
                ip = netaddr.IPAddress(ainfo[4][0])
                ip = netaddr.IPNetwork(ip)
                if ip.version == 4:
                    if ip not in self.ipv4:
                        self.ipv4.append(ip)
                else:
                    if ip not in self.ipv6:
                        self.ipv6.append(ip)
        self.resolved = True
        self.ipv4.sort()
        self.ipv6.sort()
        return self.ipv4, self.ipv6


class FWMacro(object):

    basedir = "/etc/fwmacro"
    chainsdir_ipv4 = "chains4"
    chainsdir_ipv6 = "chains6"
    chainsfile_ipv4 = "ipv4.rules"
    chainsfile_ipv6 = "ipv6.rules"
    # chainsfile_ipv6 = os.path.join(basedir, "ipv6.rules")
    logtag = "%(iface)s-%(chainname)s-%(lineno)s-%(action)s"

    rule_explanation = """\
DIRECTION ACTION [STATES] PROTOCOL OPTIONS SOURCE DESTINATION LOG [LOGLEVEL] \
[LOGNAME]

DIRECTION   := ["local"] "in" | "out"
ACTION      := "permit" | "deny" | "snat" NATARGS | "dnat" NATARGS | "masq"
STATES      := "NONE" | STATE[,STATE ...]
STATE       := "NEW" | "ESTABLISHED" | "RELATED" | "INVALID"
PROTOCOL    := "ip" | "all" | "tcp" | "udp" | "icmp" | number | `/etc/protocol`
DESTINATION := SOURCE
ADDR        := group | fqdn-hostname | ip/mask | "any"
PORT        := number | "all"
LOG         := log [syslog_level]

NATARGS     := ip[-ip] [port[-port]]

protocol ip, all, number:
SOURCE      := SRC
OPTIONS     :=

protocol icmp:
SOURCE      := SRC
OPTIONS     := [number[/code]|icmp-option]

protocol tcp:
SOURCE      := ADDR PORT
OPTIONS     := [ "syn" | "flags" [!] FMASK FCOMP ]
FMASK       := TCPFLAGS
FCOMP       := TCPFLAGS
TCPFLAGS    := "ALL"|TCPFLAG[,TCPFLAG ...]
TCPFLAG     := "SYN"|"ACK"|"FIN"|"RST"|"URG"|"PSH"|"ALL"

protocol udp:
SOURCE      := ADDR PORT
OPTIONS     :=
"""
    default_rule = """\
Default tcp state: NEW
"""
    iptables_cmd = 'iptables'
    ip6tables_cmd = 'ip6tables'
    default_icmp4options = '''
# See iptables -p icmp -h

Valid ICMP Types:
any
echo-reply (pong)
destination-unreachable
   network-unreachable
   host-unreachable
   protocol-unreachable
   port-unreachable
   fragmentation-needed
   source-route-failed
   network-unknown
   host-unknown
   network-prohibited
   host-prohibited
   TOS-network-unreachable
   TOS-host-unreachable
   communication-prohibited
   host-precedence-violation
   precedence-cutoff
source-quench
redirect
   network-redirect
   host-redirect
   TOS-network-redirect
   TOS-host-redirect
echo-request (ping)
router-advertisement
router-solicitation
time-exceeded (ttl-exceeded)
   ttl-zero-during-transit
   ttl-zero-during-reassembly
parameter-problem
   ip-header-bad
   required-option-missing
timestamp-request
timestamp-reply
address-mask-request
address-mask-reply
'''
    default_icmp6options = '''
# See ip6tables -p icmpv6 -h

Valid ICMPv6 Types:
destination-unreachable
   no-route
   communication-prohibited
   beyond-scope
   address-unreachable
   port-unreachable
   failed-policy
   reject-route
packet-too-big
time-exceeded (ttl-exceeded)
   ttl-zero-during-transit
   ttl-zero-during-reassembly
parameter-problem
   bad-header
   unknown-header-type
   unknown-option
echo-request (ping)
echo-reply (pong)
router-solicitation
router-advertisement
neighbour-solicitation (neighbor-solicitation)
neighbour-advertisement (neighbor-advertisement)
redirect
'''

    re_name = re.compile('[a-zA-Z0-9_]+')
    reserved_words = [
        "group", "interface", "ruleset",
        "local", "in", "out", "permit", "deny", "snat", "dnat", "masq",
        "ip", "tcp", "udp", "icmp", "any", "all",
        "NONE", "ESTABLISHED", "NEW", "RELATED", "INVALID",
        "ALL", "SYN", "ACK", "FIN", "RST", "URG", "PSH", "ALL", "syn", "flags",
    ]
    logging_levels = [
        "debug", "info", "notice", "warning",
        "err", "crit", "alert", "emerg",
    ]

    def __init__(self):
        self.n_errors = 0
        self.n_warnings = 0
        self.interfaces = list([
            i
            for i in netifaces.interfaces()
            if (
                netifaces.AF_LINK in netifaces.ifaddresses(i) and
                (
                    netifaces.AF_INET in netifaces.ifaddresses(i) or
                    netifaces.AF_INET6 in netifaces.ifaddresses(i)
                )
            )
        ])

    def warning(self, msg):
        self.n_warnings += 1
        sys.stderr.write("Warning: {}\n".format(msg))

    def error(self, msg):
        self.n_errors += 1
        sys.stderr.write("Error: {}\n".format(msg))

    def exec_cmd(self, cmd):
        stdoutdata = None
        try:
            p = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as err:
            self.warning("Cannot execute {}: {}".format(cmd[0], err))
        else:
            stdoutdata, stderrdata = p.communicate()
            if stderrdata:
                self.warning("Error while executing {}: {}".format(
                    ' '.join(cmd), stderrdata))
                stdoutdata = None
        return stdoutdata

    def parse_icmp_options(self, cmd, default_stdout):
        stdoutdata = self.exec_cmd(cmd) or default_stdout
        if isinstance(stdoutdata, bytes):
            stdoutdata = stdoutdata.decode()
        re_valid_types = re.compile('Valid ICMP(v6)? Types:')
        options = []
        in_option_help = False
        for line in stdoutdata.split('\n'):
            if not in_option_help:
                if re_valid_types.match(line):
                    in_option_help = True
                continue
            line = line.split('#')[0]
            if not line.strip():
                continue
            words = line.strip().split()
            assert len(words) < 3, line
            options.append(words[0])
            for word in words[1:]:
                assert word[:1] == '(' and word[-1:] == ')', word
                options.append(word[1:-1])
        if 'any' in options:
            options.remove('any')
        return options

    def get_icmp4options(self):
        iptables_cmd = '/sbin/{0}'.format(self.iptables_cmd)
        if not os.path.exists(iptables_cmd):
            iptables_cmd = self.iptables_cmd
        cmd = [iptables_cmd, '-p', 'icmp', '-h']
        self.icmp4_options = self.parse_icmp_options(
            cmd, self.default_icmp4options)
        return self.icmp4_options

    def get_icmp6options(self):
        ip6tables_cmd = '/sbin/{0}'.format(self.ip6tables_cmd)
        if not os.path.exists(ip6tables_cmd):
            ip6tables_cmd = self.ip6tables_cmd
        cmd = [ip6tables_cmd, '-p', 'icmpv6', '-h']
        self.icmp6_options = self.parse_icmp_options(
            cmd, self.default_icmp6options)
        return self.icmp6_options

    def get_protocols(self):
        protocols = [
            'all', 'tcp', 'udp', 'udplite', 'icmp', 'icmpv4', 'icmpv6',
            'esp', 'ah', 'sctp', 'mh',
        ]
        with open('/etc/protocols', 'r') as fp:
            for line in fp:
                line = line.split('#')[0].strip()
                if not line:
                    continue
                words = line.split()
                assert len(words) > 1, line
                assert int(words[1]) >= 0, line
                if not words[0] in protocols:
                    protocols.append(words[0])
                for word in words[2:]:
                    if word not in protocols:
                        protocols.append(word)
        return protocols

    def get_services(self):
        services = {}
        with open('/etc/services', 'r') as fp:
            for line in fp:
                line = line.split('#')[0].strip()
                if not line:
                    continue
                words = line.split()
                assert len(words) > 1, line
                number = int(words[1].split('/')[0])
                assert number >= 0, line
                if not words[0] in services:
                    services[words[0]] = number
                for word in words[2:]:
                    if word not in services:
                        services[word] = number
        sorted_services = list([
            i[1] for i in sorted([(len(key), key) for key in services.keys()])
        ])
        sorted_services.reverse()
        return services, sorted_services


class FWPreprocess(FWMacro):
    re_indent = re.compile('^(\s*)\S.*$')
    # re_tokens = re.compile('''((?P<q>['"]).*?(?P=q))|(\w[\w.]*)|(\W)''')
    re_tokens = re.compile(
        '''((?P<q>['"]).*?(?P=q))|'''
        '''([A-Fa-f0-9]*:[A-Fa-f0-9]*:[A-Fa-f0-9:]*)|'''
        '''(\d+[.]\d+[.]\d+[.]\d+)|'''
        '''(\d+(?!\w))|'''
        '''(\w[\w.-]*)|'''
        '''(\W)'''
    )

    def __init__(self):
        super(FWPreprocess, self).__init__()
        self.icmp4options = self.get_icmp4options()
        self.icmp6options = self.get_icmp6options()
        self.protocols = self.get_protocols()
        self.services, self.sorted_services = self.get_services()
        self.token_stack = []
        self.lineno = 0
        self.groups = {}
        self.rulesets = {}
        self.ifaces = {}
        self.addrinfos = {}
        group = Group("any", 0)
        self.any_ipv4 = netaddr.IPNetwork("0.0.0.0/0")
        self.any_ipv6 = netaddr.IPNetwork("::/0")
        group.append(self.any_ipv4)
        group.append(self.any_ipv6)
        self.groups["any"] = group
        self.force_groups = False
        self.allow_mixed_ipv = True
        self.default_log_level = 'warning'

    def get_token(self, expect_text=False, expect_indent=None,
                  expect_lineno=None):
        token = self._get_token(expect_text, expect_indent, expect_lineno)
        return token

    def _get_token(self, expect_text=False, expect_indent=None,
                   expect_lineno=None):
        if self.token_stack:
            token = self.token_stack.pop()
            if expect_text is False:
                return token
            if expect_indent is not None and expect_indent != token.indent:
                if token.indent < expect_indent:
                    raise FWIndentError(token.lineno, "-")
                raise FWIndentError(token.lineno, "+")
            if expect_lineno and token.lineno != expect_lineno:
                raise FWExpectedError(token.lineno, 'EOL')
            if expect_text is True:
                # Just expect something
                return token
            text = token.text
            if isinstance(expect_text, str):
                if text != expect_text:
                    raise FWExpectedError(token.lineno, text, expect_text)
                return token
            if text not in expect_text:
                raise FWExpectedError(token.lineno, text, expect_text)
            return token
        line = self.fp.readline()
        if not line:
            if (
                expect_text is False or
                isinstance(expect_text, list) and None in expect_text
            ):
                return None
            raise FWExpectedError(self.lineno, 'EOF', expect_text)
        self.lineno += 1
        line = line.split('#')[0]
        if not line.strip():
            return self._get_token(expect_text, expect_indent)
        try:
            indent = self.re_indent.match(line).group(1)
        except:
            self.error("line {} {}: Invalid".format(self.lineno, line))
        indent.replace('\t', '        ')
        indent = len(indent)
        for match in self.re_tokens.findall(line):
            strng, quote, ipv6, ipv4, number, text, char = match
            if quote:
                token = Token(self.lineno, indent, strng[1:-1], quote)
            elif ipv6:
                token = Token(self.lineno, indent, ipv6)
            elif ipv4:
                token = Token(self.lineno, indent, ipv4)
            elif number:
                token = Token(self.lineno, indent, number)
            elif text:
                token = Token(self.lineno, indent, text)
            elif char.strip():
                token = Token(self.lineno, indent, char)
            else:
                continue
            self.token_stack.insert(0, token)
        return self._get_token(expect_text, expect_indent)

    def push_token(self, token):
        if token is not None:
            self.token_stack.append(token)

    def skip_line(self, lineno):
        token = self.get_token()
        while token is not None and token.lineno == lineno:
            token = self.get_token()
        self.push_token(token)

    def skip_lines(self, indent):
        token = self.get_token()
        while token is not None and token.indent == indent:
            token = self.get_token()
        self.push_token(token)

    def lookup_service(self, text):
        for srvc in self.sorted_services:
            if text.startswith(srvc) and text[len(srvc)] == '-':
                return srvc, text[len(srvc):]
        return None, None

    def get_port(self, token):
        if token.text == 'all' or token.text in self.services:
            port = token.text
        else:
            try:
                port = str(int(token.text))
            except:
                raise FWInvalidPort(token.lineno, token.text)
        return port

    def get_ports(self, token):
        indent = token.indent
        lineno = token.lineno
        try:
            ports = [self.get_port(token)]
        except FWInvalidPort:
            return []
        while True:
            token = self.get_token()
            if token is None:
                return ports
            if token.lineno != lineno:
                break
            if token.text == '-':
                token = self.get_token(True, indent, lineno)
                port = self.get_port(token)
                if ports[-1] == 'all' or port == 'all':
                    raise FWSyntaxError("Cannot use 'all' in port range")
                ports[-1] = "{}-{}".format(ports[-1], port)
            elif token.text == ',':
                token = self.get_token(True, indent, lineno)
                ports.append(self.get_port(token))
            else:
                break
        if len(ports) > 1 and 'all' in ports:
            raise FWSyntaxError(
                lineno, "Cannot use 'all' with other ports")
        self.push_token(token)
        return ports

    def get_port_range(self, token):
        try:
            port_range = [self.get_port(token)]
        except FWInvalidPort:
            return []
        token = self.get_token()
        if token is None:
            return port_range
        if token.lineno != token.lineno or token.text != '-':
            self.push_token(token)
            return port_range
        token = self.get_token(True, token.indent, token.lineno)
        port_range.append(self.get_port(token))
        return port_range

    def get_name_ip_net(self, token, names_only=False):
        try:
            ip = netaddr.IPNetwork(token.text)
            if names_only:
                raise FWGroupNameRequired(token.lineno, token.text)
        except:
            if token.text != 'any' and token.text in self.reserved_words:
                raise FWSyntaxError(
                    token.lineno,
                    "Reserved word {}".format(token.text))
            return token.text
        next_token = self.get_token()
        if (
            not next_token or
            next_token.lineno != token.lineno or
            next_token.text != '/'
        ):
            self.push_token(next_token)
        else:
            mask_token = self.get_token(True, token.indent, token.lineno)
            try:
                ip = netaddr.IPNetwork("{}/{}".format(
                    token.text, mask_token.text))
            except:
                self.push_token(mask_token)
                self.push_token(next_token)
        return ip

    def get_name_ip_net_list(self, start_token, names_only=False):
        indent = start_token.indent
        lineno = start_token.lineno
        entries = [self.get_name_ip_net(start_token, names_only)]
        token = self.get_token()
        while token and token.text == ',' and token.lineno == lineno:
            entries.append(
                self.get_name_ip_net(
                    self.get_token(True, indent, lineno),
                    names_only,
                )
            )
            token = self.get_token()
        self.push_token(token)
        return entries

    def parse(self, fp):
        self.fp = fp
        self.lineno = 0
        while True:
            token = self.get_token(
                ['group', 'ruleset', 'interface', None], 0)
            if token is None:
                break
            try:
                if token.text == 'group':
                    self.handle_group(token)
                elif token.text == 'ruleset':
                    self.handle_ruleset_def(token)
                elif token.text == 'interface':
                    self.handle_interface(token)
            except FWMacroException as e:
                self.error(e)
                self.skip_line(token.lineno)
                token = self.get_token()
                if token.indent == 0:
                    self.push_token(token)
                else:
                    self.skip_lines(token.indent)
        unreferenced_ifaces = list([
            i
            for i in self.interfaces
            if (
                netifaces.AF_INET in netifaces.ifaddresses(i) or
                netifaces.AF_INET6 in netifaces.ifaddresses(i)
            )
        ])
        for name in self.ifaces:
            if name in unreferenced_ifaces:
                unreferenced_ifaces.remove(name)
            elif name[-1] == '+':
                for i in unreferenced_ifaces[:]:
                    if i.startswith(name[:-1]):
                        unreferenced_ifaces.remove(i)
        if unreferenced_ifaces:
            self.warning("Unreferenced interfaces: {}".format(
                ", ".join(unreferenced_ifaces)))

    def handle_group(self, start_token):
        token = self.get_token(True)
        name = token.text
        self.get_token(':', token.indent, token.lineno)
        if not self.re_name.match(name):
            raise FWInvalidName(token.lineno, name)
        if name not in self.groups:
            self.groups[name] = group = Group(name, start_token.lineno)
        else:
            group = self.groups[name]
            if group.lineno is None:
                group.lineno = token.lineno
            else:
                raise FWRedefinitionError(token.lineno, name, group.lineno)
        token = self.get_token(True)
        indent = token.indent
        if indent <= start_token.indent:
            raise FWIndentError(token.lineno, '+')
        while token is not None and token.indent == indent:
            text = self.get_name_ip_net(token)
            if not isinstance(text, str):
                group.append(text)
            else:
                if text not in self.groups:
                    # Forward reference to a group
                    if '.' in text:
                        # Hostname (to be resolved later)
                        self.groups[text] = Hostname(text, None)
                    else:
                        self.groups[text] = Group(text, None)
                self.groups[text].referred_lines.append(token.lineno)
                group.append(self.groups[text])
            next_token = self.get_token()
            if token.lineno == next_token.lineno:
                raise FWExpectedError(token.lineno, next_token.text, 'EOL')
            token = next_token
        if token.indent != start_token.indent:
            raise FWIndentError(token.lineno, None)
        if token is not None:
            self.push_token(token)

    def handle_ruleset_def(self, start_token):
        token = self.get_token(True)
        name = token.text
        if name in self.rulesets:
            raise FWRedefinitionError(
                token.lineno, name, 'ruleset')
        self.get_token(':', token.indent, token.lineno)
        rules = self.handle_rules(start_token)
        self.rulesets[name] = rules

    def handle_interface(self, start_token):
        token = self.get_token(True)
        name = token.text
        if name in self.ifaces:
            raise FWRedefinitionError(
                token.lineno, name, 'interface')
        if name not in self.interfaces:
            matched = False
            if name[-1] == '+':
                for i in self.interfaces:
                    if i.startswith(name[:-1]):
                        matched = True
                        break
            if not matched:
                self.warning("No matching interfaces for {}".format(name))
        self.get_token(':', token.indent, token.lineno)
        rules = self.handle_rules(start_token)
        self.ifaces[name] = rules

    def handle_rules(self, start_token):
        rules = []
        token = self.get_token(True)
        indent = token.indent
        if indent <= start_token.indent:
            raise FWIndentError(token.lineno, None)
        while token is not None and token.indent == indent:
            try:
                rule = self.handle_rule(token)
                if isinstance(rule, list):
                    rules.extend(rule)
                else:
                    rules.append(rule)
            except FWMacroException as e:
                self.error(e)
                # Skip current line
                self.skip_line(token.lineno)
            token = self.get_token()
        if token is not None:
            if token.indent != start_token.indent:
                raise FWIndentError(token.lineno, None)
            self.push_token(token)
        return rules

    def handle_rule(self, start_token):
        lineno = start_token.lineno
        indent = start_token.indent

        def get_nat_ip(token):
            text = token.text
            if text in self.groups:
                # test if it is a group and make sure it only contains one IP
                if len(self.groups[text]) != 1:
                    raise FWSyntaxError(
                        token.lineno, "NAT ip group can only have 1 item")
                else:
                    self.groups[text].resolve()
                    text = str(self.groups[text].ips()[0]).split('/')[0]
            elif self.force_groups:
                raise FWGroupNameRequired(token.lineno, text)
            else:
                # Handle ip address
                try:
                    text = str(netaddr.IPAddress(text))
                except:
                    raise FWInvalidIP(token.lineno, text)
            return text

        # Until we have a destination, all self.get_token should return
        # in a token on the same line. So, at least arguments:
        # True, indent, lineno
        token = start_token
        expect = ['in', 'out']
        is_local = False
        if token.text == 'ruleset':
            token = self.get_token(True, indent, lineno)
            if token.text not in self.rulesets:
                raise FWUndefinedError(
                    lineno, token.text, "ruleset")
            return self.rulesets[token.text]
        elif token.text == 'local':
            is_local = True
            token = self.get_token(expect, indent, lineno)
        elif token.text not in expect:
            raise FWExpectedError(start_token.lineno, token.text, expect)
        rule = Rule(lineno, is_local, token.text)
        token = self.get_token(
            ["permit", "deny", "snat", "dnat", "masq"], indent, lineno)
        rule.action = token.text
        token = self.get_token(True, indent, lineno)

        if rule.action in ["snat", "dnat"]:
            # Read NATARGS
            # NATARGS := ip[-ip] [port[-port]]
            nat_ip = [get_nat_ip(token)]
            token = self.get_token(True, indent, lineno)
            if token.text != '-':
                rule.nat = nat_ip[0]
            else:
                token = self.get_token(True, indent, lineno)
                nat_ip.append(get_nat_ip(token))
                rule.nat = '-'.join(nat_ip)
                token = self.get_token(True, indent, lineno)
            rule.natports = '-'.join([
                str(i) for i in self.get_port_range(token)])
            if rule.natports:
                token = self.get_token(True, indent, lineno)

        # STATES := "NONE" | STATE[,STATE ...]
        # STATE := "NEW" | "ESTABLISHED" | "RELATED" | "INVALID"
        # Default is NEW
        states = []
        while (
            token.text in [
                "NONE", "NEW", "ESTABLISHED", "RELATED", "INVALID",
            ]
        ):
            if token.lineno != lineno:
                self.push_token(token)
                raise FWExpectedError(lineno, 'EOL')
            text = "" if token.text == "NONE" else token.text
            if text not in states:
                states.append(text)
            token = self.get_token(True, indent, lineno)
        if states:
            if len(states) > 1 and "" in states:
                FWSyntaxError("Cannot mix state NONE with other states")
            rule.state = ",".join(states)

        # PROTOCOL := "ip" | "all" | "tcp" | "udp" | "icmp" | number |
        # `/etc/protocol`
        invert = ''
        if token.text == '!':
            invert = '!'
            token = self.get_token(True, indent, lineno)
        try:
            proto = int(token.text)
        except:
            if (
                token.text in ["ip", "all", "tcp", "udp", "icmp", ] or
                token.text in self.protocols
            ):
                proto = token.text
            else:
                raise FWExpectedError(lineno, token.text, 'protocol')
        if proto in ["ip", "all", 0]:
            if invert:
                raise FWSyntaxError(
                    "Cannot invert protocol {}".format(proto)
                )
            proto = "all"
        rule.protocol = "{}{}".format(invert, proto)
        token = self.get_token(True, indent, lineno)
        if rule.action in ["dnat"]:
            if proto in ["tcp", "udp"]:
                if not rule.natports:
                    raise FWSyntaxError(
                        "Specific ports needed in nat definition "
                        "(when using tcp or udp match condition)"
                    )
            elif rule.natports:
                raise FWSyntaxError(
                    "Ports not used in nat definition "
                    "(use tcp or udp match condition)"
                )

        # Get proto options
        if proto == 'icmp':
            icmp4 = []
            icmp6 = []
            while True:
                is_option = False
                if token.text in self.icmp4_options:
                    icmp4.append(token.text)
                    is_option = True
                if token.text in self.icmp6_options:
                    icmp6.append(token.text)
                    is_option = True
                if not is_option:
                    break
                token = self.get_token(True, indent, lineno)
                if token.text == ',':
                    token = self.get_token(True, indent, lineno)
                else:
                    break
            rule.icmp4 = icmp4
            rule.icmp6 = icmp6
        elif proto == 'tcp':
            # OPTIONS  := [ "syn" | "flags" [!] FMASK FCOMP ]
            # FMASK    := TCPFLAGS
            # FCOMP    := TCPFLAGS
            # TCPFLAGS := "ALL"|TCPFLAG[,TCPFLAG ...]
            # TCPFLAG  := "SYN"|"ACK"|"FIN"|"RST"|"URG"|"PSH"|"ALL"

            tcp_fmask = []
            tcp_fcomp = []
            if token.text == 'syn':
                rule.tcpflags = [token.text]
            elif token.text == 'flags':
                token = self.get_token(
                    ['!', "ALL", "SYN", "ACK", "FIN", "RST", "URG", "PSH", ],
                    indent, lineno)
                invert = False
                if token.text == '!':
                    invert = True
                    token = self.get_token(
                        ["ALL", "SYN", "ACK", "FIN", "RST", "URG", "PSH", ],
                        indent, lineno)
                tcp_fmask.append(token.text)
                token = self.get_token(True, indent, lineno)
                while token.text == ',':
                    token = self.get_token(
                        ["ALL", "SYN", "ACK", "FIN", "RST", "URG", "PSH", ],
                        indent, lineno)
                    tcp_fmask.append(token.text)
                    token = self.get_token(True, indent, lineno)
                self.push_token(token)
                token.text = ','
                while token.text == ',':
                    token = self.get_token(
                        ["ALL", "SYN", "ACK", "FIN", "RST", "URG", "PSH", ],
                        indent, lineno)
                    tcp_fcomp.append(token.text)
                    token = self.get_token(True, indent, lineno)
                rule.tcpflags = [','.join(tcp_fmask), ','.join(tcp_fcomp)]
                if invert:
                    rule.tcpflags[0] = '!{}'.format(rule.tcpflags[0])

        # Now get the source
        addrs = self.get_name_ip_net_list(token, self.force_groups)
        if len(addrs) == 0:
            raise FWExpectedError(lineno, token.text, 'source address')
        if len(addrs) > 1 and 'any' in addrs:
            raise FWSyntaxError(
                lineno, "Cannot mix 'any' with other source addresses")
        rule.sources = addrs
        token = self.get_token(True, indent, lineno)

        if proto in ["tcp", "udp"]:
            # Get tcp/udp ports
            rule.srcports = self.get_ports(token)
            if not rule.srcports:
                raise FWExpectedError(lineno, token.text, 'source port')
            token = self.get_token(True, indent, lineno)

        # Now get the destination
        addrs = self.get_name_ip_net_list(token, self.force_groups)
        if len(addrs) == 0:
            raise FWExpectedError(lineno, token.text, 'destination address')
        if len(addrs) > 1 and 'any' in addrs:
            raise FWSyntaxError(
                lineno, "Cannot mix 'any' with other destination addresses")
        rule.destinations = addrs

        # Now we have to be careful with get_token()

        if proto in ["tcp", "udp"]:
            token = self.get_token(True, indent, lineno)
            # Get tcp/udp ports
            rule.dstports = self.get_ports(token)
            if not rule.dstports:
                raise FWExpectedError(lineno, token.text, 'destination port')

        token = self.get_token()
        # Check for logging
        if token and token.lineno == lineno and token.text == "log":
            rule.logging = self.default_log_level
            token = self.get_token()
            if token and token.lineno == lineno:
                if token.text in self.logging_levels:
                    rule.logging = token.text
                    token = self.get_token()
                if (
                    token.lineno == lineno and
                    token.text not in self.logging_levels
                ):
                    rule.logname = token.text
                    token = self.get_token()

        if token is not None:
            if token.lineno == lineno:
                raise FWExpectedError(lineno, token.text, 'EOL')
            self.push_token(token)
        return rule

    def resolve_ip(self, targets, rule):
        """Resolve all targets to ip networks"""
        all_ip4 = []
        all_ip6 = []
        all_ip = []
        all_targets = []
        for name in targets:
            if name[0] == "!":
                invert = "!"
                name = name[1:]
                self.error("Cannot invert addresses")
            else:
                invert = ""
            ips = []
            try:
                ip = netaddr.IPNetwork(name)
                if ip.network != ip.ip:
                    self.error(
                        FWIPMaskBoundaryError(ip, rule.lineno))
                ips = [ip]
            except netaddr.core.AddrFormatError as e:
                if name in self.groups and \
                   self.groups[name].lineno is not None:
                    ips = self.groups[name].ips()
                elif name.find(".") != -1:
                    hostname = Hostname(name, rule.lineno)
                    try:
                        hostname.resolve()
                        ips = hostname.ips()
                    except FWResolveError as e:
                        self.error(e)
                else:
                    e = FWUndefinedError(rule.lineno, name, 'group')
                    self.error(e)
            for ip in ips:
                ipinfo = (ip.prefixlen, ip, invert)
                if ipinfo not in all_ip:
                    all_ip.append((ip.prefixlen, ip, invert))
        all_ip.sort()
        all_ip.reverse()
        last_ip = last_invert = None
        for prefixlen, ip, invert in all_ip:
            if last_ip is not None:
                if last_ip == ip:
                    if last_invert != invert:
                        self.error(
                            "Conflicting definitions ({}, !{},{})"
                            "at line {}"
                        ).format(ip, invert, last_invert, rule.lineno)
                    continue
            last_ip = ip
            last_invert = invert
            for target_ip, target_invert in all_targets:
                if (
                    target_ip.size != 1 and (
                        (target_ip[0] >= ip[0] and target_ip[0] <= ip[-1]) or
                        (target_ip[-1] >= ip[0] and target_ip[1] <= ip[-1]) or
                        (ip[0] >= target_ip[0] and ip[0] <= target_ip[-1]) or
                        (ip[-1] >= target_ip[0] and ip[-1] <= target_ip[-1])
                    )
                ):
                    self.warning(
                        "Overlapping ranges ({}, {}) at line {}".format(
                            ip, target_ip, rule.lineno))
            all_targets.append((ip, invert))
            if ip.version == 4:
                all_ip4.append((invert, ip))
            elif ip.version == 6:
                all_ip6.append((invert, ip))
            else:
                self.error("Invalid ip version for {} at line {}".format(
                    ip, rule.lineno))
        return all_ip4, all_ip6

    def resolve_ports(self, ports, rule):
        if len(ports) == 1:
            if ports[0] == "all":
                return [], [""]
        all = []
        for port in ports:
            all += port.split(",")
        ports = all
        all = []
        for port in ports:
            if port[0] == "!":
                invert = "!"
            else:
                invert = ""
            if port.find("-") != -1:
                p1, p2 = port.split("-")
                p1 = int(p1)
                p2 = int(p2)
                all.append((p1, p2, invert))
            else:
                p = int(port)
                all.append((p, p, invert))
        all_raw = all
        all_raw.sort()
        all = []
        while len(all_raw):
            p1a = all_raw[0][0]
            p2a = all_raw[0][1]
            pia = all_raw[0][2]
            del(all_raw[0])
            while len(all_raw):
                p1b = all_raw[0][0]
                p2b = all_raw[0][1]
                pib = all_raw[0][2]
                if p1b <= p2a + 1:
                    if pia != pib:
                        self.error(
                            "Conflicting port definition at line {}".format(
                                rule.lineno))
                        break
                    if p2a < p2b:
                        p2a = p2b
                    del(all_raw[0])
                    continue
                break
            all.append((p1a, p2a, pia))
        comma_ports = []
        range_ports = []
        for p1, p2, invert in all:
            if invert and len(all) > 1:
                self.error((
                    "Cannot use '!' on multiple port definitions "
                    "at line {}"
                ).format(rule.lineno))
                return [], []
            if p1 == p2:
                if not invert:
                    if len(all) == 1:
                        range_ports.append("{}".format(p1))
                    else:
                        comma_ports.append("{}".format(p1))
                else:
                    comma_ports.append("!{}".format(p1))
            else:
                range_ports.append("{}{}:{}".format(invert, p1, p2))
        all = comma_ports
        comma_ports = []
        while len(all):
            comma_ports.append(",".join(all[:15]))
            del(all[:15])
        if not comma_ports and not range_ports:
            return [], [""]
        return comma_ports, range_ports

    def resolve(self):
        for group in self.groups.values():
            try:
                group.resolve()
            except FWRecursionError as e:
                self.error(e)
            except FWResolveError as e:
                self.error(e)
        for name, group in self.groups.items():
            if (
                group.lineno is None and
                not isinstance(group, Hostname)
            ):
                raise FWUndefinedError(group.referred_lines[0], name, 'group')

    def purge_default(self, src):
        dst = []
        for ip in src:
            if ip[1] != self.any_ipv4 and ip[1] != self.any_ipv6:
                dst.append(ip)
        return dst

    def make_rule(self, chainnr, chainname, iface, rule):
        if not rule:
            if self.n_errors == 0:
                self.error("Invalid rule in interface {}: {}".format(
                    iface, chainname))
            return "", ""
        # Get all source ips
        srcs_ip4, srcs_ip6 = self.resolve_ip(rule.sources, rule)
        dsts_ip4, dsts_ip6 = self.resolve_ip(rule.destinations, rule)
        if not srcs_ip4 and dsts_ip4:
            dsts_ip4 = self.purge_default(dsts_ip4)
        if srcs_ip4 and not dsts_ip4:
            srcs_ip4 = self.purge_default(srcs_ip4)
        if not srcs_ip6 and dsts_ip6:
            dsts_ip6 = self.purge_default(dsts_ip6)
        if srcs_ip6 and not dsts_ip6:
            srcs_ip6 = self.purge_default(srcs_ip6)
        if (
            not self.allow_mixed_ipv and (
                (srcs_ip4 and not dsts_ip4) or
                (dsts_ip4 and not srcs_ip4) or
                (srcs_ip6 and not dsts_ip6) or
                (dsts_ip6 and not srcs_ip6)
            )
        ):
            self.error((
                "Cannot mix IPv4 and IPv6 source and "
                "destination at line {}"
            ).format(rule.lineno))
        lines_ip4 = []
        lines_ip6 = []
        line_ipv4 = []
        line_ipv6 = []
        targets = []
        if rule.nat or rule.action == "masq":
            line_ipv4 += ["-t nat"]
            if not srcs_ip4 or not dsts_ip4:
                self.error("NAT rule only valid for IPv4 at line {}".format(
                    rule.lineno))
            else:
                all = netaddr.IPNetwork("::/0")
                for src in srcs_ip6:
                    if src[1] != all:
                        self.warning((
                            "Ignoring {} rule for IPv6 source address {} "
                            "at line {}"
                        ).format(rule.action, src, rule.lineno))
                for dst in dsts_ip6:
                    if dst[1] != all:
                        self.warning((
                            "Ignoring {} rule for IPv6 destination "
                            "address {} at line {}"
                        ).format(rule.action, dst, rule.lineno))
        else:
            line_ipv4 += ["-t filter"]
            line_ipv6 += ["-t filter"]
        if rule.logging:
            lineno = rule.lineno
            action = rule.action
            if rule.logname:
                s = rule.logname
            else:
                s = self.logtag % locals()
            if len(s) > 27:
                s = s[:20] + "..." + s[-5:]
            # iptables-restore needs strings in "" and not ''
            targets.append((
                'LOG --log-prefix "{} " --log-level {} -m limit '
                '--limit 60/minute --limit-burst 10').format(s, rule.logging))
        if rule.direction == "in":
            line_ipv4 += ["-i", iface]
            line_ipv6 += ["-i", iface]
        elif rule.direction == "out":
            line_ipv4 += ["-o", iface]
            line_ipv6 += ["-o", iface]
        else:
            self.error("Invalid direction {}".format(
                rule.direction, rule.lineno))
        chainname = rule.chainname(chainnr, chainname, iface)
        line_ipv4 += ["-p", rule.protocol]
        if rule.protocol == 'icmp':
            line_ipv6 += ["-p", 'icmpv6']
        else:
            line_ipv6 += ["-p", rule.protocol]
        if srcs_ip4:
            for icmp_type in rule.icmp4:
                line_ipv4 += ['--icmp-type', icmp_type]
        if srcs_ip6:
            for icmp_type in rule.icmp6:
                line_ipv6 += ['--icmpv6-type', icmp_type]
        if rule.state:
            if rule.protocol == 'icmp':
                line_ipv4 += ["-m state --state", rule.state]
            else:
                line_ipv4 += ["-m state --state", rule.state]
                line_ipv6 += ["-m state --state", rule.state]
        line_ipv4 += ["-A {}{}".format(100 + chainnr, chainname)]
        line_ipv6 += ["-A {}{}".format(100 + chainnr, chainname)]
        if rule.nat:
            if rule.natports:
                nat = "{}:{}".format(rule.nat, rule.natports)
            else:
                nat = rule.nat
            if rule.action == "snat":
                targets.append("SNAT")
                line_ipv4 += ["-j %(target)s --to-source", nat]
            else:
                targets.append("DNAT")
                line_ipv4 += ["-j %(target)s --to-destination", nat]
        else:
            if rule.action == "permit":
                if rule.direction == "in" and \
                  not rule.local:
                    targets.append("RETURN")
                else:
                    targets.append("ACCEPT")
                line_ipv4 += ["-j %(target)s"]
                line_ipv6 += ["-j %(target)s"]
            elif rule.action == "deny":
                targets.append("DROP")
                line_ipv4 += ["-j %(target)s"]
                line_ipv6 += ["-j %(target)s"]
            elif rule.action == "masq":
                targets.append("MASQUERADE")
                line_ipv4 += ["-j %(target)s"]
                line_ipv6 += ["-j %(target)s"]
        line_ipv4_start = " ".join(line_ipv4)
        line_ipv6_start = " ".join(line_ipv6)
        # Get all src ports (two lists: ranges and comma sep)
        src_comma_ports, src_range_ports = self.resolve_ports(
            rule.srcports, rule)
        # Get all destination ips
        destinations = self.resolve_ip(rule.destinations, rule)
        # Get all dst ports (two lists: ranges and comma sep)
        dst_comma_ports, dst_range_ports = self.resolve_ports(
            rule.dstports, rule)
        if rule.nat:
            sources = srcs_ip4
            destinations = dsts_ip4
        else:
            sources = srcs_ip4 + srcs_ip6
            destinations = dsts_ip4 + dsts_ip6
        for src_invert, src_ip in sources:
            if src_ip.version == 4:
                line_start = line_ipv4_start
                lines = lines_ip4
            else:
                line_start = line_ipv6_start
                lines = lines_ip6
            if src_ip.prefixlen == 0:
                src = ""
            else:
                src = "--src {}{}/{}".format(
                    src_invert, src_ip.ip, src_ip.prefixlen)
            for dst_invert, dst_ip in destinations:
                if rule.nat and src_ip.version != 4:
                    continue
                if src_ip.version != dst_ip.version:
                    continue
                if dst_ip.prefixlen == 0:
                    dst = ""
                else:
                    dst = "--dst {}{}/{}".format(
                        dst_invert, dst_ip.ip, dst_ip.prefixlen)
                for sport in src_comma_ports:
                    for dport in dst_comma_ports:
                        for target in targets:
                            lines.append(" ".join([
                                line_start % {"target": target},
                                src, "-m multiport --sports", sport,
                                dst, "-m multiport --dports", dport,
                            ]))
                    for dport in dst_range_ports:
                        if dport != "":
                            dport = "--dport {}".format(dport)
                        for target in targets:
                            lines.append(" ".join([
                                line_start % {"target": target},
                                src, "-m multiport --sports", sport,
                                dst, dport,
                            ]))
                for sport in src_range_ports:
                    if sport != "":
                        sport = "--sport {}".format(sport)
                    for dport in dst_comma_ports:
                        for target in targets:
                            lines.append(" ".join([
                                line_start % {"target": target},
                                src, sport,
                                dst, "-m multiport --dports", dport,
                            ]))
                    for dport in dst_range_ports:
                        if dport != "":
                            dport = "--dport {}".format(dport)
                        for target in targets:
                            lines.append(" ".join([
                                line_start % {"target": target},
                                src, sport,
                                dst, dport,
                            ]))
        return [
            line.strip() for line in lines_ip4
        ], [
            line.strip() for line in lines_ip6
        ]

    def make_rules(self):
        chains4 = {}
        chains6 = {}
        ifaces_keys = list(self.ifaces.keys())
        ifaces_keys.sort()
        for iface in ifaces_keys:
            chain_idx = 0
            chain = 'ifs'
            chain_idx += 1
            lines_ip4 = []
            lines_ip6 = []
            filename = "fwm-{}".format(chain)
            for rule in self.ifaces[iface]:
                rule_ip4, rule_ip6 = self.make_rule(
                    chain_idx, chain, iface, rule)
                if not rule_ip4 and not rule_ip6:
                    self.warning((
                        "Nothing to do for {} rule for IPv4 and IPv6 "
                        "at line {}"
                    ).format(rule.action, rule.lineno))
                lines_ip4 += rule_ip4
                lines_ip6 += rule_ip6
            if filename in chains4:
                chains4[filename] += lines_ip4
            else:
                chains4[filename] = lines_ip4
            if filename in chains6:
                chains6[filename] += lines_ip6
            else:
                chains6[filename] = lines_ip6
        return chains4, chains6

    def write_rules(self, chains4, chains6):
        if self.n_errors != 0:
            return
        for chainsdir, chains in [
            (self.chainsdir_ipv4, chains4),
            (self.chainsdir_ipv6, chains6),
        ]:
            chainsdir = os.path.join(self.basedir, chainsdir)
            if not os.path.isdir(chainsdir):
                self.error("Not a directory: {}".format(chainsdir))
        if self.n_errors != 0:
            return
        for chainsdir, chains in [
            (self.chainsdir_ipv4, chains4),
            (self.chainsdir_ipv6, chains6),
        ]:
            chainsdir = os.path.join(self.basedir, chainsdir)
            chains_keys = list(chains.keys())
            chains_keys.sort()
            for chainname in chains_keys:
                fname = "{}/{}".format(chainsdir, chainname)
                try:
                    fp = open(fname, "w")
                    fp.write("{}\n".format("\n".join(chains[chainname])))
                    fp.close()
                except IOError as why:
                    self.error("Failed to write to file {}: {}".format(
                        fname, why))
            for fname in os.listdir(chainsdir):
                if fname[:4] != "fwm-":
                    continue
                if fname not in chains:
                    os.unlink(os.path.join(chainsdir, fname))


class FWCompile(FWMacro):

    tables = []

    reserved_targets = [
        # Always there
        "ACCEPT",
        "DROP",
        "QUEUE",
        "RETURN",

        # Target extensions
        "CLASSIFY",
        "CLUSTERIP",
        "CONNMARK",
        "CONNSECMARK",
        "DNAT",
        "DSCP",
        "ECN",
        "HL",
        "LOG",
        "MARK",
        "MASQUERADE",
        "MIRROR",
        "NETMAP",
        "NFLOG",
        "NFQUEUE",
        "NOTRACK",
        "RATEEST",
        "REDIRECT",
        "REJECT",
        "SAME",
        "SECMARK",
        "SET",
        "SNAT",
        "TCPMSS",
        "TCPOPTSTRIP",
        "TOS",
        "TRACE",
        "TTL",
        "ULOG",
    ]
    re_ignore_chain_file = re.compile("([.].*)|(CVS)")
    re_heading = re.compile("target\s+prot\s+opt\s+source\s+destination")
    re_policy = re.compile("Chain ([^ ]+) [(]policy .*")
    re_chain = re.compile("Chain ([^ ]+) [(].* references.*")
    re_jump = re.compile("([^ ]+).+all.+--.+0.0.0.0/0.+0.0.0.0/0.*")
    re_get_table = re.compile("-t ([^ ]+)")
    re_get_chain = re.compile("-A ([^ ]+)")
    re_numchain = re.compile("(\d+)(.*)")
    re_chaindef = re.compile("(\d+)?(.*:)?(.*)")
    re_table_rule = re.compile("(.*)(-t \S+)(.*)")
    builtin_chains = {
        "filter": ["INPUT", "OUTPUT", "FORWARD"],
        "nat": ["PREROUTING", "POSTROUTING", "OUTPUT"],
        "mangle": ["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"],
        "raw": ["PREROUTING", "OUTPUT"],
    }

    def __init__(self, remove_all_chains=False, verbose=False):
        self.remove_all_chains = remove_all_chains
        self.verbose = verbose
        self.n_errors = 0
        self.n_warnings = 0
        self.newchains = {}
        self.filechains = {}
        self.reserved_chains = {}
        for table in self.tables:
            self.reserved_chains[table] = []

    def log(self, level, msg):
        sys.stderr.write("{}\n".format(msg))

    # def log_error(self, msg, lineno=None):
    #     if self.n_errors > 10:
    #         sys.exit(1)
    #     self.n_errors += 1
    #     if lineno is not None:
    #         self.log(syslog.LOG_ERR, "line %d, %s" % (lineno, msg))
    #         return
    #     self.log(syslog.LOG_ERR, "%s" % msg)

    # def log_warning(self, msg, lineno=None):
    #     self.nwarnings += 1
    #     if lineno is not None:
    #         self.log(syslog.LOG_WARNING, "line %d, %s" % (lineno, msg))
    #         return
    #     self.log(syslog.LOG_WARNING, "%s" % msg)

    def parentchains(self, table, chain):
        match = self.re_chaindef.match(chain)
        parentchains = self.builtin_chains[table]
        short = chain.split("-")[0]
        if short == "IN":
            parentchains = ["INPUT"]
        elif short == "OUT":
            parentchains = ["OUTPUT"]
        elif short == "FWD":
            parentchains = ["FORWARD"]
        elif short == "PRE":
            parentchains = ["PREROUTING"]
        elif short == "POST":
            parentchains = ["POSTROUTING"]
        if len(parentchains) == 1 and \
           parentchains[0] not in self.builtin_chains[table]:
            raise FWInvalidParentChain(table, chain)
        if table == "filter":
            if match.group(2):
                # Local rules are in chains that start with eighter
                # I or O. Other rules start with i or o.
                if match.group(2)[0] == "I":
                    parentchains = ["INPUT"]
                elif match.group(2)[0] == "O":
                    parentchains = ["OUTPUT"]
                else:
                    parentchains = ["FORWARD"]
        elif table == "nat":
            if match.group(2):
                if match.group(2)[0] == "i":
                    parentchains = ["PREROUTING"]
                elif match.group(2)[0] == "o":
                    parentchains = ["POSTROUTING"]
        elif table == "mangle":
            if match.group(2):
                if match.group(2)[0] == "i":
                    parentchains = ["INPUT", "PREROUTING", "FORWARD"]
                elif match.group(2)[0] == "o":
                    parentchains = ["OUTPUT", "POSTROUTING", "FORWARD"]
        return parentchains

    def read_chain_file(self, fpath):
        try:
            fp = open(fpath, "r")
            data = fp.read()
            fp.close()
        except IOError as why:
            sys.stderr.write(
                "Error reading file '{}': {}\n".format(fpath, why))
            sys.exit(1)
        return data

    def read_chain_files(self, chainsfiles):
        chainsfiles.sort()

        chainorder = {}
        for table in self.tables:
            self.newchains[table] = {}
            chainorder[table] = {}

        if not self.remove_all_chains:
            for fname in chainsfiles:
                if self.re_ignore_chain_file.match(fname):
                    continue
                self.filechains[fname] = {}
                for table in self.tables:
                    self.filechains[fname][table] = {}
                fpath = "{}/{}".format(self.chainsdir, fname)
                data = self.read_chain_file(fpath)
                lines = data.split("\n")
                linenr = 0
                for line in lines:
                    linenr += 1
                    line = line.split("#")[0]
                    line = line.strip()
                    m = self.re_get_table.search(line)
                    if m:
                        table = m.group(1)
                    else:
                        table = "filter"
                    m = self.re_get_chain.search(line)
                    if not m:
                        # Hmm... No chain name?
                        continue
                    num = 50
                    chain = m.group(1)
                    m = self.re_chaindef.match(chain)
                    if m:
                        num = int(m.group(1))
                        if m.group(2):
                            newchain = "{}{}".format(m.group(2), m.group(3))
                        else:
                            newchain = m.group(3)
                        line = line.replace(
                            "-A {}".format(chain), "-A {}".format(newchain))
                        chain = newchain
                    if chain in self.reserved_chains[table]:
                        raise FWReservedChainName(chain, fname, linenr)
                    if chain not in self.filechains[fname][table]:
                        self.filechains[fname][table][chain] = []
                    self.filechains[fname][table][chain].append(line)
                    self.newchains[table][(num, chain)] = 1
                    if chain not in chainorder[table]:
                        chainorder[table][chain] = (num, fname, linenr)
                    elif chainorder[table][chain][0] != num:
                        raise FWOrderConflict(
                            chain,
                            fname,
                            linenr,
                            (chainorder[table][chain]),
                        )

        for table in self.tables:
            sortchains = list(self.newchains[table].keys())
            sortchains.sort()
            self.newchains[table] = []
            for order, chain in sortchains:
                if chain not in self.newchains[table]:
                    self.newchains[table].append(chain)

    def generate_restore_file(self, rule_file):
        targets = {}
        rules = {}
        for table in self.tables:
            targets[table] = []
            rules[table] = []
            for chain in self.newchains[table]:
                if table not in self.tables:
                    raise FWInvalidTable(table)
                targets[table].append(chain)
                parentchains = self.parentchains(table, chain)
                for pchain in parentchains:
                    m = self.re_chaindef.match(chain)
                    if m.group(2):
                        iface = m.group(2)[1:-1]
                        direction = m.group(2)[0].lower()
                        rules[table].append("-A {} -{} {} -j {}".format(
                            pchain, direction, iface, chain))
                    else:
                        rules[table].append("-A {} -j {}".format(
                            pchain, chain))
        for table in self.tables:
            for chain in self.newchains[table]:
                for fname in self.filechains.keys():
                    if chain in self.filechains[fname][table]:
                        for line in self.filechains[fname][table][chain]:
                            match = self.re_table_rule.match(line)
                            if match:
                                line = "{} {}".format(
                                    match.group(1).strip(),
                                    match.group(3).strip(),
                                )
                            rules[table].append(line.strip())

        if rule_file == "-" or not rule_file:
            fp = sys.stdout
        elif hasattr(rule_file, "seek"):
            fp = rule_file
        else:
            fp = open(rule_file, "w")
        fp.write("# Generated with {} {} at {}\n".format(
            self.__class__.__name__,
            ".".join([str(i) for i in __version__]),
            time.ctime(),
        ))
        for table in self.tables:
            fp.write("*{}\n".format(table))
            if self.remove_all_chains or table != "filter":
                policy = "ACCEPT"
            else:
                policy = "DROP"
            for target in self.builtin_chains[table]:
                fp.write(":{} {} [0:0]\n".format(target, policy))

            for target in targets[table]:
                fp.write(":{} - [0:0]\n".format(target))
            for rule in rules[table]:
                fp.write("{}\n".format(rule))
            fp.write("COMMIT\n")


class FWCompileIPv4(FWCompile):

    tables = ["raw", "mangle", "nat", "filter"]


class FWCompileIPv6(FWCompile):

    tables = ["filter", "mangle"]


def fwmpp():
    import optparse

    parser = optparse.OptionParser(
        usage="""\
usage: %%prog [options] FILE

Rule format:
{pp.rule_explanation}
Defaults:
{pp.default_rule}
ICMP options:
{pp.default_icmp4options}
ICMPv6 options:
{pp.default_icmp6options}
""".format(pp=FWPreprocess))

    parser.add_option(
        "-V", "--version",
        action="store_true",
        dest="version",
        default=False,
        help="show version and exit",
    )
    parser.add_option(
        "--base",
        dest="basedir",
        default="/etc/fwmacro",
        metavar="DIRECTORY",
        help="Set the base path (default: '{}')".format(FWMacro.basedir),
    )
    parser.add_option(
        "--ipv4-chains",
        action="store",
        dest="chainsdir_ipv4",
        default=FWPreprocess.chainsdir_ipv4,
        metavar="DIRECTORY",
        help="directory with iptables chains (default: {})".format(
             FWPreprocess.chainsdir_ipv4),
    )
    parser.add_option(
        "--ipv6-chains",
        action="store",
        dest="chainsdir_ipv6",
        default=FWPreprocess.chainsdir_ipv6,
        metavar="DIRECTORY",
        help="directory with ip6tables chains (default: {})".format(
            FWPreprocess.chainsdir_ipv6),
    )
    parser.add_option(
        "--logtag",
        action="store",
        dest="logtag",
        default=FWPreprocess.logtag,
        help="log tag template (default: '%s')" % FWPreprocess.logtag,
    )
    parser.add_option(
        "--force-groups",
        action="store_true",
        dest="force_groups",
        default=False,
        help="Force the use of groups (default: '%s')" % False,
    )

    opts, args = parser.parse_args()
    if opts.version:
        print("Version: {}".format(".".join([str(i) for i in __version__])))
        sys.exit(0)

    if len(args) > 1:
        sys.stderr.write("Too many arguments")
        sys.exit(1)
    fpp = FWPreprocess()
    fpp.basedir = os.path.abspath(opts.basedir)
    fpp.chainsdir_ipv4 = opts.chainsdir_ipv4
    fpp.chainsdir_ipv6 = opts.chainsdir_ipv6
    fpp.logtag = opts.logtag
    fpp.force_groups = opts.force_groups

    try:
        if not args:
            fpp.parse(sys.stdin)
        else:
            fpp.parse(open(args[0], 'r'))
        fpp.resolve()
        chains4, chains6 = fpp.make_rules()
    except FWMacroException as e:
        fpp.error(e)
        sys.exit(1)
    if fpp.n_errors == 0:
        fpp.write_rules(chains4, chains6)
    else:
        sys.stderr.write("Errors (%s)\n" % fpp.n_errors)
        sys.exit(1)
    sys.exit(0)


def fwmc():
    import optparse

    parser = optparse.OptionParser(
        usage="""\
usage: %prog [options] start | stop
""",
    )

    parser.add_option(
        "-V", "--version",
        action="store_true",
        dest="version",
        default=False,
        help="show version and exit",
    )
    parser.add_option(
        "--verbose",
        action="store_true",
        dest="verbose",
        default=False,
        help="verbose messages",
    )
    parser.add_option(
        "--base",
        dest="basedir",
        default="/etc/fwmacro",
        metavar="DIRECTORY",
        help="Set the base path (default: '{}')".format(FWMacro.basedir),
    )
    parser.add_option(
        "--ipv4-rules",
        action="store",
        dest="ipv4_rules",
        default=FWCompile.chainsfile_ipv4,
        help="filename of generated iptables-restore file",
    )
    parser.add_option(
        "--ipv6-rules",
        action="store",
        dest="ipv6_rules",
        default=FWCompile.chainsfile_ipv6,
        help="filename of generated ip6tables-restore file",
    )
    parser.add_option(
        "--no-ipv4",
        action="store_false",
        dest="ipv4",
        default=True,
        help="no iptables chains (ipv4)",
    )
    parser.add_option(
        "--no-ipv6",
        action="store_false",
        dest="ipv6",
        default=True,
        help="no ip6tables chains (ipv6)",
    )
    parser.add_option(
        "--ipv4-chains",
        action="store",
        dest="chainsdir_ipv4",
        default=FWCompile.chainsdir_ipv4,
        metavar="DIRECTORY",
        help="directory with iptables chains (default: {})".format(
            FWCompile.chainsdir_ipv4),
    )
    parser.add_option(
        "--ipv6-chains",
        action="store",
        dest="chainsdir_ipv6",
        default=FWCompile.chainsdir_ipv6,
        metavar="DIRECTORY",
        help="directory with ip6tables chains (default: {})".format(
            FWCompile.chainsdir_ipv6),
    )
    parser.add_option(
        "--reserved-target",
        action="append",
        dest="reserved_targets",
        default=FWCompile.reserved_targets,
        help=(
            "reserved target (e.g. ACCEPT) that "
            "will not be mapped to a chain"
        ),
    )

    def no_reserved_target(option, opt_str, value, parser, *args, **kwargs):
        FWCompile.reserved_targets.remove(value)

    parser.add_option(
        "--no-reserved-target",
        type="string",
        action="callback",
        callback=no_reserved_target,
        help="not a reserved target (remove from reserved targets list)",
    )
    parser.add_option(
        "--help-reserved-target",
        action="store_true",
        dest="help_reserved_target",
        default=False,
        help="show help on reserved targets",
    )

    default_reserved_targets = [] + FWCompile.reserved_targets
    opts, args = parser.parse_args()
    if opts.version:
        print("Version: {}".format(".".join([str(i) for i in __version__])))
        sys.exit(0)
    if opts.help_reserved_target:
        print("Default reserved targets:")
        indent = 4 * " "
        line = ""
        while default_reserved_targets:
            if line:
                new_line = ", ".join([line, default_reserved_targets[0]])
            else:
                new_line = default_reserved_targets[0]
            if len(new_line) < 80 - len(indent):
                line = new_line
                del(default_reserved_targets[0])
            elif not line:
                print ("{}{}".format(indent, new_line))
                del(default_reserved_targets[0])
            else:
                print("{}{}".format(indent, line))
                line = ""
        sys.exit(0)

    if len(args) == 0:
        args = ["start"]
    elif len(args) != 1:
        sys.stderr.write("Too many arguments\n")
        sys.exit(1)
    if args[0] not in ["start", "stop"]:
        sys.stderr.write("Invalid argument '%s'\n" % args[0])
        sys.exit(1)

    remove_all_chains = False
    if args[0] in ["stop"]:
        remove_all_chains = 1

    if opts.ipv4:
        fc = FWCompileIPv4(
            remove_all_chains=remove_all_chains,
            verbose=opts.verbose,
        )
        fc.basedir = os.path.abspath(opts.basedir)
        fc.chainsdir = opts.chainsdir_ipv4
        chainsfiles = os.listdir(fc.chainsdir)
        try:
            fc.read_chain_files(chainsfiles)
            fc.generate_restore_file(opts.ipv4_rules)
        except FWMacroException as e:
            fc.error(e)
    if opts.ipv6:
        fc = FWCompileIPv6(
            remove_all_chains=remove_all_chains,
            verbose=opts.verbose,
        )
        fc.basedir = os.path.abspath(opts.basedir)
        fc.chainsdir = opts.chainsdir_ipv6
        chainsfiles = os.listdir(fc.chainsdir)
        try:
            fc.read_chain_files(chainsfiles)
            fc.generate_restore_file(opts.ipv6_rules)
        except FWMacroException as e:
            fc.error(e)
    sys.exit(0)


def main():
    progname = os.path.basename(sys.argv[0])
    if progname in ["fwmpp", "fwmpp.py"]:
        fwmpp()
    elif progname in ["fwmc", "fwmc.py"]:
        fwmc()
    elif len(sys.argv) > 1 and sys.argv[1] == '--fwmpp':
        del(sys.argv[0])
        fwmpp()
    elif len(sys.argv) > 1 and sys.argv[1] == '--fwmc':
        del(sys.argv[0])
        fwmc()
    else:
        sys.stderr.write("Invalid invocation as '%s'\n" % progname)
        exit(1)


if __name__ == '__main__':
    main()
