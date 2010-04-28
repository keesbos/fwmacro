#!/usr/bin/env python
#
# Copyright (c) 2010, ZX. All rights reserved.
#
# Released under the MIT license. See LICENSE file for details.
#

__version__ = (0, 9, 0)

import sys
import socket
import os
import os.path
import re
import syslog
import time
try:
    import netaddr
except:
    sys.stderr.write("""\
Cannot import netaddr.
Either:
	easy_install netaddr
or
	install your distributions python-netaddr package
""")
    raise
try:
    from plex import *
except:
    sys.stderr.write("""\
Cannot import plex.
Either:
	easy_install plex
or
	install your distributions python-plex package
""")
    raise


BASEDIR = "/etc/fwmacro"
CHAINSDIR_IPV4 = os.path.join(BASEDIR, "chains4")
CHAINSDIR_IPV6 = os.path.join(BASEDIR, "chains6")
CHAINSFILE_IPV4 = os.path.join(BASEDIR, "ipv4.rules")
CHAINSFILE_IPV6 = os.path.join(BASEDIR, "ipv6.rules")


rule_explanation = """\
DIRECTION ACTION STATES PROTOCOL OPTIONS SOURCE DESTINATION LOG [LOGLEVEL] [LOGNAME]

DIRECTION   := ["local"] "in" | "out"
ACTION      := "permit" | "deny" | "snat" NATARGS | "dnat" NATARGS | "masq"
STATES      := "NONE" | STATE[,STATE ...]
STATE       := "ESTABLISHED" | "NEW" | "RELATED" | "INVALID"
PROTOCOL    := "ip" | "all" | "tcp" | "udp" | "icmp" | number | `/etc/protocol`
DESTINATION := SOURCE
ADDR        := group | hostname | ip/mask | "any"
PORT        := number | "all"
LOG         := log [syslog_level]

NATARGS     := ip[-ip] [port[-port]]

protocol ip, all, number:
SOURCE      := SRC
OPTIONS     :=

protocol icmp:
SOURCE      := SRC
OPTIONS     := icmp-option [/number]

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

defaults_txt = """\
Default tcp state: NEW
"""

# iptables -p icmp -h
icmp_options_txt = """\
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
"""


invalid_names = []
reserved_words = ["group", "interface", "ruleset",
    "local", "in", "out", "permit", "deny", "snat", "dnat", "masq",
    "ip", "tcp", "udp", "icmp", "any", "all", 
    "NONE", "ESTABLISHED", "NEW", "RELATED", "INVALID", 
    "ALL", "SYN", "ACK", "FIN", "RST", "URG", "PSH", "ALL", "syn", "flags",
    ]
logging_levels = ["debug", "info", "notice", "warning", 
                  "err", "crit", "alert", "emerg"]
invalid_names = invalid_names + reserved_words + logging_levels
for line in icmp_options_txt.split("\n"):
    line = line.strip().split()
    if line:
        line = line[0].strip()
        invalid_names.append(line)

default_log_level = "warning"


class FWMacroException(Exception):
    """Base exception for fwmacro"""
    pass


class FWUndefinedGroup(FWMacroException):
    """Undefined group"""

    def __init__(self, name, lineno):
        FWMacroException.__init__(self, name, lineno)
        self.name = name
        self.lineno = lineno

    def log_message(self):
        return "Undefined group %s" % self.args[0]


class FWGroupRedefinition(FWMacroException):
    """Redefinition of a group detected"""

    def __init__(self, name, lineno, group):
        FWMacroException.__init__(self, name, lineno, group)
        self.name = name
        self.lineno = lineno
        self.group = group

    def log_message(self):
        return "Redefinition of group '%s' defined at line %d" % (self.name, self.group.lineno)


class FWRecursion(FWMacroException):
    """Recursion detected in resolving names"""

    def __init__(self, *groups):
        FWMacroException.__init__(self, *groups)
        self.name = groups[0].name
        self.lineno = groups[0].lineno

    def log_message(self):
        groups = list(self.args)
        lines = []
        for group in groups:
            lines.append("%d: %s" % (group.name, group.lineno))
        return "Recursion detected in group definition for group %s: %s" % (
            groups[0].name,
            ", ".join(lines),
        )


class FWResolveError(FWMacroException):
    """Resolve error for hostnames"""

    def __init__(self, name, errmsg, lineno):
        FWMacroException.__init__(self, name, errmsg, lineno)
        self.name = name
        self.errmsg = errmsg
        self.lineno = lineno

    def log_message(self):
        if self.errmsg:
            return "Cannot resolve %s: %s" % (self.name, self.errmsg)
        return "Cannot resolve %s" % self.name


class FWIPMaskBoundaryError(FWMacroException):
    """IP not on lower mask boundary"""

    def __init__(self, ip, lineno):
        FWMacroException.__init__(self, ip, lineno)
        self.ip = ip
        self.lineno = lineno

    def log_message(self):
        return "IP is not on mask boundary (%s)" % self.ip


class FWInvalidTable(FWMacroException):
    def log_message(self):
        return "Invalid table name '%s'" % self.args[0]


class FWInvalidParentChain(FWMacroException):
    def __init__(self, table, chain):
        self.table = table
        self.chain = chain

    def log_message(self):
        return "Invalid parent chain '%s' in table '%s'" % (
            self.chain,
            self.table,
        )

class FWReservedChainName(FWMacroException):
    def __init__(self, chain, fname, lineno):
        self.chain = chain
        self.fname = fname
        self.lineno = lineno

    def log_message(self):
        return "Reserved chain name '%s' at %s:%s" % (
            self.chain,
            self.fname,
            self.lineno,
        )

class FWOrderConflict(FWMacroException):
    def __init__(self, chain, fname, lineno, origdef):
        self.chain = chain
        self.fname = fname
        self.lineno = lineno
        self.origdef = origdef

    def log_message(self):
        return "Order redefinition of chain '%s' at %s:%s (first defined at %s:%s)" % (
            self.chain,
            self.fname,
            self.lineno,
            self.origdef[1],
            self.origdef[2],
        )


class Rule(object):
    """Represention of a input (FWPreprocess) rule"""

    def __init__(self, lineno, local, direction):
        self.lineno = lineno
        self.local = local
        self.direction = direction
        self.action = None
        self.protocol = None
        self.icmp = []
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

    def __str__(self):
        return "line: %s, local: %s, direction: %s, action: %s" % (
            self.lineno, self.local, self.direction, self.action,
        )

    def __repr__(self):
        return "<Rule %s>" % self.__str__()

    def chainname(self, chainnr, chainname, iface):
        if self.local:
            direction_char = self.direction[0].upper()
        else:
            direction_char = self.direction[0].lower()
        chainname = "%s%s:%s" % (direction_char, iface, chainname)
        if len(chainname) >= 30:
            chainname = "%s%s:%d%s" % (iface, direction_char, chainnr, chainname)
            chainname = chainname[:29]
        return chainname


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
        if not self.cached.has_key(self.name):
            self.cached[self.name] = self
        if self.resolved is False:
            raise FWRecursion([self])
        if self.resolved is None:
            self.resolved = False
            for obj in self:
                ipv4, ipv6 = [], []
                if hasattr(obj, "resolve"):
                    try:
                        ipv4, ipv6 = obj.resolve()
                    except FWRecursion, e:
                        raise FWRecursion(e[0] + [self])
                else:
                    assert(isinstance(obj, netaddr.IPNetwork))
                    if obj.version == 4:
                        ipv4 = [obj]
                    else:
                        ipv6 = [obj]
                for ip in ipv4:
                    if not ip in self.ipv4:
                        if ip.network != ip.ip:
                            raise FWIPMaskBoundaryError(ip)
                        self.ipv4.append(ip)
                for ip in ipv6:
                    if not ip in self.ipv6:
                        if ip.network != ip.ip:
                            raise FWIPMaskBoundaryError(ip)
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
        if not self.cached.has_key(self.name):
            self.cached[self.name] = self
        if self.resolved is None:
            self.resolved = False
            try:
                ainfos = socket.getaddrinfo(self.name, None)
            except socket.gaierror, why:
                raise FWResolveError(self.name, why[1], self.lineno)
            except:
                raise FWResolveError(self.name, None, self.lineno)
            for ainfo in ainfos:
                ip = netaddr.IPAddress(ainfo[4][0])
                ip = netaddr.IPNetwork(ip)
                if ip.version == 4:
                    if not ip in self.ipv4:
                        self.ipv4.append(ip)
                else:
                    if not ip in self.ipv6:
                        self.ipv6.append(ip)
        self.resolved = True
        self.ipv4.sort()
        self.ipv6.sort()
        return self.ipv4, self.ipv6


class FWPreprocess(Scanner):

    #
    # First the methods that implement the grammar and scanning 
    # of the source file.
    #

    def current_level(self):
        return self.indentation_stack[-1]

    def newline_action(self, text):
        if self.bracket_nesting_level == 0:
            self.begin("indent")
            return "newline"

    def indentation_action(self, text):
        # Check that tabs and spaces are being used consistently.
        if text:
            c = text[0]
            if self.indentation_char is None:
                self.indentation_char = c
            else:
                if self.indentation_char <> c:
                    self.log_error("Mixed up tabs and spaces!")
        # Figure out how many indents/dedents to do
        current_level = self.current_level()
        new_level = len(text)
        if new_level > current_level:
            self.indent_to(new_level)
        elif new_level < current_level:
            self.dedent_to(new_level)
        # Change back to default state
        self.begin("")

    def indent_to(self, new_level):
        self.indentation_stack.append(new_level)
        self.produce("INDENT", "")

    def dedent_to(self, new_level):
        while new_level < self.current_level():
            del self.indentation_stack[-1]
            self.produce("DEDENT", "")
        if new_level <> self.current_level():
            self.log_error("Indentation error")

    def eof(self):
        self.dedent_to(0)

    def state_end_action(self, text):
        self.begin("")
        return "state-end"

    def ip_action(self, text):
        self.begin("ip")
        return "ip"

    def tcp_action(self, text):
        self.begin("tcp")
        return "tcp"

    def udp_action(self, text):
        self.begin("udp")
        return "udp"

    def icmp_action(self, text):
        self.begin("icmp")
        return "icmp"

    resword = Str("group", "interface", "ruleset",
                  "local", "in", "out", 
                  "permit", "deny", "snat", "dnat", "masq",
                  "log", 
                 )
    resword = apply(Str, tuple(reserved_words))
    letter = Range("AZaz") | Any("_")
    digit = Range("09")
    hexdigit = Range("09AFaf")

    name = Rep1(letter | digit | Any("_-"))
    number = Rep1(digit) | (Str("0x") + Rep1(hexdigit))

    sq_string = (
        Str("'") +
        Rep(AnyBut("\\\n'") | (Str("\\") + AnyChar)) +
        Str("'"))

    dq_string = (
        Str('"') +
        Rep(AnyBut('\\\n"') | (Str("\\") + AnyChar)) +
        Str('"'))

    non_dq = AnyBut('"') | (Str("\\") + AnyChar)
    tq_string = (
        Str('"""') +
        Rep(
            non_dq |
            (Str('"') + non_dq) |
            (Str('""') + non_dq)) + Str('"""'))

    stringlit = sq_string | dq_string | tq_string
    opening_bracket = Any("([{")
    closing_bracket = Any(")]}")
    punct1 = Any("!:,;+-*/|&<>=.%`~^")
    punct2 = Str("==", "<>", "!=", "<=", "<<", ">>", "**")
    punctuation = punct1 | punct2

    spaces = Rep1(Any(" \t"))
    opt_space = Rep(Any(" \t"))
    comma_sep = opt_space + Str(",") + opt_space
    indentation = Rep(Str(" ")) | Rep(Str("\t"))
    lineterm = Str("\n") | Eof
    escaped_newline = Str("\\\n")
    comment = Str("#") + Rep(AnyBut("\n"))
    blank_line = indentation + Opt(comment) + lineterm
    ip4 = number + Any(".") + number + Any(".") + number + Any(".") + number
    ip4 = number + Any(".") + number + Any(".") + number + Any(".") + number
    ip6number = Rep1(hexdigit) | ip4
    ip6 = Rep(ip6number + Any(":")) + ip6number
    ip6 = ip6 | Opt(ip6) + Str("::") + Opt(ip6)
    hostname = name + Rep(Any(".") + name)
    conn_state = Str("ESTABLISHED", "NEW", "RELATED", "INVALID", "NONE")
    conn_states = conn_state + Rep(Opt(Any(" \t")) + Str(",") + Opt(Any(" \t")) + conn_state)
    conn_states = conn_state + Rep(comma_sep + conn_state)
    tcp_syn = Opt(Str("!") + opt_space) + Str("syn")
    tcp__flags = Str("NONE")
    for f in ["SYN","ACK","FIN","RST","URG","PSH","ALL"]:
        tcp__flags |= Str(f)
    tcp_flags = Opt(Str("!") + opt_space) + tcp__flags + Rep(comma_sep + tcp__flags)
    icmp_types = None
    for t in icmp_options_txt.split("\n"):
         t = t.split("(")[0]
         t = t.strip()
         if t:
             if icmp_types is None:
                 icmp_types = Str(t)
             else:
                 icmp_types |= Str(t)
    icmp_type = (icmp_types | number) + Opt(opt_space + Str("/") + opt_space + number)
    l3_mask = opt_space + Str("/") + opt_space + (number | ip4 | ip6)
    l3_hostname = Opt(Str("!") + opt_space) + hostname
    l3_ip = Opt(Str("!") + opt_space) + (ip4 | ip6) + Opt(l3_mask)
    l3_name = Opt(Str("!") + opt_space) + name
    l3 = Opt(Str("!") + opt_space) + (((ip4 | ip6) + Opt(l3_mask)) | name | hostname)
    layer3 = l3 + Rep(opt_space + Str(",") + opt_space + l3)
    layer4_range = (name | number) + Opt(opt_space + Str("-") + opt_space + (name | number))
    layer4 = layer4_range + Rep(opt_space + Str(",") + opt_space + layer4_range)
    nat_layer3 = opt_space + ip4 + Opt(opt_space + Str("-") + opt_space + ip4)
    nat_layer4 = Str("all") | (number + Opt(opt_space + Str("-") + opt_space + number))# + spaces
    log_levels = apply(Str, tuple(logging_levels))

    lexicon = Lexicon([
        (Str("ip"),         ip_action),
        (Str("tcp"),        tcp_action),
        (Str("udp"),        udp_action),
        (Str("icmp"),       icmp_action),
        (resword,           TEXT),
        (ip4,               "ip4"),
        (ip6,               "ip6"),
        (name,              "name"),
        (hostname,          "hostname"),
        (number,            "number"),
        (stringlit,         "string"),
        (punctuation,       TEXT),
        (lineterm,          newline_action),
        (comment,           IGNORE),
        (spaces,            IGNORE),
        (escaped_newline,   IGNORE),
        State("indent", [
            (blank_line,    IGNORE),
            (indentation,   indentation_action),
        ]),
        State("conn-state", [
            (conn_states,   "conn-state"),
            (spaces,        IGNORE),
            (Empty,         state_end_action),
        ]),
        State("ip", [
            (spaces,        IGNORE),
            (Empty,         state_end_action),
        ]),
        State("tcp", [
            (tcp_syn,       "syn"),
            (Str("flags"),  "flags"),
            (tcp_flags,     "tcp-flags"),
            (spaces,        IGNORE),
            (Empty,         state_end_action),
        ]),
        State("udp", [
            (spaces,        IGNORE),
            (Empty,         state_end_action),
        ]),
        State("icmp", [
            (icmp_type,     "icmp-type"),
            (spaces,        IGNORE),
            (Empty,         state_end_action),
        ]),
        State("layer3", [
            (layer3,        "layer3"),
            (spaces,        IGNORE),
            (Empty,         state_end_action),
        ]),
        State("layer4", [
            (layer4,        "layer4"),
            (spaces,        IGNORE),
            (Empty,         state_end_action),
        ]),
        State("nat-layer3", [
            (nat_layer3,    "nat-layer3"),
            (spaces,        IGNORE),
            (Empty,         state_end_action),
        ]),
        State("nat-layer4", [
            (nat_layer4,    "nat-layer4"),
            (spaces,        IGNORE),
            (Empty,         state_end_action),
        ]),
    ])

    #
    # Now all the methods etc. that implement the parsing
    # and interpretation of the input file.
    #

    nerrors = 0
    nwarnings = 0
    chainsdir_ip4 = CHAINSDIR_IPV4
    chainsdir_ip6 = CHAINSDIR_IPV6
    chainname = "ifs"
    logtag = "%(iface)s-%(chainname)s-%(lineno)s-%(action)s"

    def __init__(self, fname):
        if fname in [None, "-"]:
            fp = sys.stdin
        elif hasattr(fname, "seek"):
            fp = fname
        else:
            fp = open(fname)

        Scanner.__init__(self, self.lexicon, fp)
        self.lineno = 1
        self.indentation_stack = [0]
        self.bracket_nesting_level = 0
        self.indentation_char = None
        self.begin("indent")

        self.groups = {}
        self.ifaces = {}
        self.chainorder = {}
        self.rulesets = {}
        self.addrinfos = {}
        self.protocols = self.read_protocols()
        group =  Group("any", 0)
        group.append(netaddr.IPNetwork("0.0.0.0/0"))
        group.append(netaddr.IPNetwork("::/0"))
        self.groups["any"] = group

    def read_protocols(self, fname="/etc/protocols"):
        """Get the protocol name/number mapping from /etc/protocols"""
        protocols = {}
        try:
            fp = open(fname)
        except:
            fp = None
        if fp is not None:
            while True:
                line = fp.readline()
                if not line:
                    break
                line = line.split("#")[0]
                line = line.strip()
                if not line:
                    continue
                try:
                    name1, number, name2 = line.split(None, 3)
                    number = int(number)
                except:
                    name1 = None
                if name1 is not None:
                    protocols[name1] = number
                    protocols[name2] = number
        return protocols

    def log(self, level, msg):
        sys.stderr.write("%s\n" % msg)

    def log_error(self, msg, lineno = None):
        if self.nerrors > 10:
            sys.exit(1)
        self.nerrors += 1
        if lineno is not None:
            self.log(syslog.LOG_ERR, "line %d, %s" % (lineno, msg))
            return
        p = self.position()
        if p:
            if p[1]:
                self.log(syslog.LOG_ERR, "line %d:%d, %s" % (p[1], p[2], msg))
                return
        self.log(syslog.LOG_ERR, "%s" % msg)

    def log_warning(self, msg, lineno = None):
        self.nwarnings += 1
        if lineno is not None:
            self.log(syslog.LOG_WARNING, "line %d, %s" % (lineno, msg))
            return
        p = self.position()
        if p:
            if p[1]:
                self.log(syslog.LOG_WARNING, "line %d:%d, %s" % (p[1], p[2], msg))
                return
        self.log(syslog.LOG_WARNING, "%s" % msg)

    def skip_this_line(self, token = None, text = None):
        """Ignore all remaning tokens of the current line"""
        while token != "newline":
            token, text = self.read()
        return token, text

    def validate_ports(self, ports, proto = "", lineno = None):
        """Check ports for valid names/ranges"""
        ports = ports.replace(" ", "").lower()
        if ports == "all":
            return [], []
        port_list_range = []
        port_list_comma = []
        for port in ports.split(","):
            p = port.split("-")
            try:
                p0 = int(p[0])
            except:
                try:
                    p0 = socket.getservbyname(p[0], proto)
                except socket.error, why:
                    self.log_error("%s '%s'" % (why, p[0]))
                    return None
            if len(p) == 1:
                port_list_comma.append(str(p0))
                continue
            if len(p) != 2:
                self.log_error("Invalid port definition '%s'" % port)
                return None
            try:
                p1 = int(p[1])
            except:
                try:
                    p1 = socket.getservbyname(p[1], proto)
                except socket.error, why:
                    self.log_error("%s '%s'" % (why, p[1]))
                    return None
            if p0 == p1:
                port_list_comma.append(str(p0))
            elif p0 < p1:
                port_list_range.append("%s-%s" % (p0, p1))
            else:
                port_list_range.append("%s-%s" % (p1, p0))
        return port_list_range, port_list_comma

    def get_group(self, level):
        """Read a group section"""
        if level != 0:
            self.log_error("Unexpected token 'group'")
        token, text = self.read()
        if token != "name":
            self.log_error("Identifier excpected, got '%s'" % token)
        groupname = text
        if self.groups.has_key(text):
            group = self.groups[groupname]
            if group.lineno is not None:
                e = FWGroupRedefinition(text, self.lineno, group)
                self.log_error(e.log_message())
            group.lineno = self.lineno
        else:
            group = Group(text, self.lineno)
        token, text = self.read()
        if token != ":":
            self.log_error("':' expected")
        else:
            token, text = self.read()
        if token != "newline":
            self.log_error("Newline expected")
            token, text = self.skip_this_line()
        token, text = self.read()
        if token != "INDENT":
            self.log_error("Indent expected")
            return
        while 1:
            token, text = self.read()
            if token == "DEDENT":
                break
            if token == "ip4":
                name = text 
                token, text = self.read()
                if token == "/":
                    token, text = self.read()
                    mask = int(text)
                    if mask > 32:
                        self.log_error("Invalid IPv4 mask")
                    token, text = self.read()
                else:
                    mask = 32
                ip = netaddr.IPNetwork("%s/%s" % (name, mask))
                group.append(ip)
                if token == "newline":
                    continue
            elif token == "ip6":
                name = text
                token, text = self.read()
                if token == "/":
                    token, text = self.read()
                    mask = int(text)
                    if mask > 128:
                        self.log_error("Invalid IPv6 mask")
                    token, text = self.read()
                else:
                    mask = 128
                ip = netaddr.IPNetwork("%s/%s" % (name, mask))
                group.append(ip)
                if token == "newline":
                    continue
            elif token == "hostname":
                name = text
                token, text = self.read()
                if token == "newline":
                    if not self.groups.has_key(name):
                        self.groups[name] = Hostname(name, None)
                    self.groups[name].referred_lines.append(self.position()[1])
                    group.append(self.groups[name])
                    continue
            elif token == "name":
                name = text
                token, text = self.read()
                if token == "newline":
                    if not self.groups.has_key(name):
                        self.groups[name] = Group(name, None)
                    self.groups[name].referred_lines.append(self.position()[1])
                    group.append(self.groups[name])
                    continue
            self.log_error("Unexpected '%s'" % text)
            token, text = self.skip_this_line()
        if level == 0:
            self.groups[groupname] = group

    def get_rule(self, direction):
        """Read a rule line"""
        is_local = False
        if direction == "local":
            is_local = True
            token, text = self.read()
            if not token in ["in", "out"]:
                self.log_error("Invalid direction '%s'" % text)
                token, text = self.skip_this_line()
                return None
            direction = token
        rule = Rule(self.position()[1], is_local, direction)
        token, text = self.read()
        if not token in ["permit", "deny", "snat", "dnat", "masq"]:
            self.log_error("Invalid action '%s'" % text)
            token, text = self.skip_this_line()
            return None
        rule.action = token
        if rule.action in ["snat", "dnat"]:
            # Read NAT options
            if rule.action == "snat":
                directionstr = "Source"
            else:
                directionstr = "Destination"

            self.begin("nat-layer3")
            token, text = self.read()
            if token == "newline":
                self.log_error("Nat address expected")
                self.begin("")
                return None
            if token == "nat-layer3":
                rule.nat = text.replace(" ", "")
            elif token == "state-end":
                self.log_error("Invalid nat address")
                self.begin("")
                self.skip_this_line()
                return None
            else:
                self.log_error("Unknown token: %s" % [token, text])
                self.begin("")
                self.skip_this_line()
                return None

            self.begin("nat-layer4")
            token, text = self.read()
            if token == "newline":
                self.log_error("%s expected" % directionstr)
                self.begin("")
                return None
            if token == "nat-layer4":
                rule.natports = text.replace(" ", "")
                r = rule.natports.split("-")
                if r[0] == "all":
                    if len(r) != 1:
                        self.log_error("Invalid port '%s'" % text)
                    rule.natports = None
                self.begin("")
            elif token == "state-end":
                pass
            else:
                self.log_error("Unknown token: %s" % [token, text])
                self.begin("")
                self.skip_this_line()
                return None

        self.begin("conn-state")
        token, text = self.read()
        if token == "conn-state":
            text = text.replace(" ", "")
            if text.find("NONE") == -1:
                rule.state = text
            else:
                rule.state = ""
                if text != "NONE":
                    self.log_error("Cannot combine state NONE with other states")
        elif token == "state-end":
            pass

        self.begin("")
        token, text = self.read()
        if text == "!":
            invert = "!"
            token, text = self.read()
        else:
            invert = ""
        if not token in ["ip", "all", "icmp", "tcp", "udp", "number"]:
            self.log_error("Invalid protocol '%s'" % text)
            token, text = self.skip_this_line()
            return None
        if rule.action in ["dnat"]:
            if token in ["tcp", "udp"]:
                if not rule.natports:
                    self.log_error("Specific ports needed in nat definition (when using tcp or udp match condition)")
                    token, text = self.skip_this_line()
                    return None
            else:
                if rule.natports:
                    self.log_error("Ports not used in nat definition (use tcp or udp match condition)")
                    token, text = self.skip_this_line()
                    return None

        if text == "ip" or text == "all":
            if invert:
                self.log_error("Cannot invert protocol '%s'" % text)
            text = "all"
        if token == "number":
            self.begin("ip")
        rule.protocol = "%s%s" % (invert, text)
        # Get proto options (State = rule.protocol)
        while 1:
            token, text = self.read()
            if token == "state-end":
                break
            if token == "newline":
                self.begin("")
                return None
            elif token == "syn":
                text = text.replace(" ", "")
                if rule.tcpflags:
                    self.log_error("Cannot combine 'syn' with other flags")
                else:
                    rule.tcpflags = [text]
            elif token == "flags":
                token, text = self.read()
                if token != "tcp-flags":
                    self.log_error("Expected tcp flags")
                    token, text = self.skip_this_line()
                    return None
                flags_mask = text.replace(" ", "")
                token, text = self.read()
                if token != "tcp-flags":
                    self.log_error("Expected tcp flags")
                    token, text = self.skip_this_line()
                    return None
                flags_match = text.replace(" ", "")
                if flags_match[0] == "!":
                    self.log_error("Match flags cannot start with '!'")
                if rule.tcpflags:
                    self.log_error("Cannot combine flags")
                else:
                    rule.tcpflags = [flags_mask, flags_match]
            elif token == "icmp-type":
                rule.icmp.append(text.replace(" ", ""))
            else:
                self.log_error("Unknown token: %s" % [token, text])
                self.skip_this_line()
                return None

            
        # Now get the source
        self.begin("layer3")
        token, text = self.read()
        if token == "newline":
            self.log_error("Source expected")
            self.begin("")
            return None
        if token == "layer3":
            text = text.replace(" ", "")
            if text != "any":
                for s in text.split():
                    if s in invalid_names:
                        self.log_error("Invalid source '%s'" % s)
            rule.sources += text.split(",")
        elif token == "state-end":
            self.log_error("Invalid source")
            self.begin("")
            self.skip_this_line()
            return None
        else:
            self.log_error("Unknown token: %s" % [token, text])
            self.begin("")
            self.skip_this_line()
            return None
        
        if rule.protocol in ["tcp", "udp"]:
            self.begin("layer4")
            # Get source ports
            token, text = self.read()
            if token == "newline":
                self.log_error("Source port expected")
                self.begin("")
                return None
            if token == "layer4":
                p = text.replace(" ", "").lower()
                if not self.validate_ports(p, rule.protocol):
                    self.begin("")
                    self.skip_this_line()
                    return None
                rule.srcports.append(text.replace(" ", ""))
            elif token == "state-end":
                self.log_error("Invalid source port")
                self.begin("")
                self.skip_this_line()
                return None
            else:
                self.log_error("Unknown token: %s" % [token, text])
                self.begin("")
                self.skip_this_line()
                return None
        
        # Now get the destination
        self.begin("layer3")
        token, text = self.read()
        if token == "newline":
            self.log_error("Destination expected")
            self.begin("")
            return None
        if token == "layer3":
            text = text.replace(" ", "")
            if text != "any":
                for s in text.split():
                    if s in invalid_names:
                        self.log_error("Invalid destination '%s'" % s)
            rule.destinations += text.split(",")
        elif token == "state-end":
            self.log_error("Invalid destination")
            self.begin("")
            self.skip_this_line()
            return None
        else:
            self.log_error("Unknown token: %s" % [token, text])
            self.begin("")
            self.skip_this_line()
            return None
        
        if rule.protocol in ["tcp", "udp"]:
            self.begin("layer4")
            # Get destination ports
            token, text = self.read()
            if token == "newline":
                self.log_error("Destination port expected")
                self.begin("")
                return None
            if token == "layer4":
                p = text.replace(" ", "").lower()
                if not self.validate_ports(p, rule.protocol):
                    self.begin("")
                    self.skip_this_line()
                    return None
                rule.dstports.append(text.replace(" ", ""))
            elif token == "state-end":
                self.log_error("Invalid destination port")
                self.begin("")
                self.skip_this_line()
                return None
            else:
                self.log_error("Unknown token: %s" % [token, text])
                self.begin("")
                self.skip_this_line()
                return None
        
        self.begin("")
        # Check for logging
        token, text = self.read()
        if text == "log":
            rule.logging = default_log_level
            token, text = self.read()
            if text in logging_levels:
                rule.logging = text
                token, text = self.read()
            if token != "newline":
                if not text in logging_levels:
                    rule.logname = text
                else:
                    self.log_error("Invalid logname: %s" % text)
                    self.begin("")
                    self.skip_this_line()
                    return None
        
        # Done (should ...)
        if token == "newline":
            return rule
        
        self.log_error("Garbage at end of line: '%s'" % text)
        token, text = self.skip_this_line()
        return None

    def get_rules(self):
        """Get all rules define in a section (interface/ruleset)"""
        rules = []
        while 1:
            token, text = self.read()
            if token == "DEDENT":
                break
            elif token in ["local", "in", "out"]:
                lineno = self.position()[1]
                rule = self.get_rule(token)
                rules.append(rule)
                continue
            elif token == "ruleset":
                token, text = self.read()
                if token != "name":
                    self.log_error("Identifier excpected, got '%s'" % token)
                else:
                    if self.rulesets.has_key(text):
                        rules = rules + self.rulesets[text]
                    else:
                        self.log_error("Undefined ruleset '%s'" % text)
            else:
                self.log_error("Unexpected '%s'" % text)
                self.skip_this_line()
                continue
            token, text = self.read()
            if token == "newline":
                pass
            else:
                self.log_error("Unexpected '%s'" % text)
        return rules

    def get_ruleset(self, level):
        """Parse a ruleset section"""
        token, text = self.read()
        if token != "name":
            self.log_error("Identifier excpected, got '%s'" % token)
        if self.rulesets.has_key(text):
            self.log_error("Duplicate ruleset definition %s" % text)
        ruleset_name = text
        self.rulesets[ruleset_name] = []
        token, text = self.read()
        if token != ":":
            self.log_error("':' expected")
        token, text = self.read()
        if token != "newline":
            self.log_error("Newline expected")
        token, text = self.read()
        if token != "INDENT":
            self.log_error("Indent expected")
        self.rulesets[ruleset_name] = self.get_rules()

    def get_interface(self, level):
        """Parse a interface section"""
        token, text = self.read()
        if token != "name":
            self.log_error("Identifier excpected, got '%s'" % token)
        if self.ifaces.has_key(text):
            self.log_error("Duplicate interface definition %s" % text)
        if len(text) > 25:
            self.log_error("Interface name too long")
        iface = []
        chains = {}
        ifacename = text
        self.chainorder[ifacename] = []
        chainname = self.chainname
        self.chainorder[ifacename].append(chainname)
        chains[chainname] = []
        token, text = self.read()
        if token != ":":
            self.log_error("':' expected")
        token, text = self.read()
        if token != "newline":
            self.log_error("Newline expected")
        token, text = self.read()
        if token != "INDENT":
            self.log_error("Indent expected")
        chains[chainname] = self.get_rules()
        if level == 0:
            self.ifaces[ifacename] = chains
        return
        while 1:
            token, text = self.read()
            if token == "DEDENT":
                break
            elif token in ["local", "in", "out"]:
                lineno = self.position()[1]
                rule = self.get_rule(token)
                chains[chainname].append(rule)
                continue
            elif token == "ruleset":
                token, text = self.read()
                if token != "name":
                    self.log_error("Identifier excpected")
                else:
                    if self.rulesets.has_key(text):
                        chains[chainname] = chains[chainname] + self.rulesets[text]
                    else:
                        self.log_error("Undefined ruleset '%s'" % text)
            else:
                self.log_error("Unexpected '%s'" % text)
                self.skip_this_line()
                continue
            token, text = self.read()
            if token == "newline":
                pass
            else:
                self.log_error("Unexpected '%s'" % text)
        if level == 0:
            self.ifaces[ifacename] = chains

    def read_fwrules(self):
        """Read the firewall definition groups/rulesets/interface rules"""
        self.trace = 0
        level = 0
        while 1:
            token, text = self.read()
            if token is None:
                    break
            if token == "INDENT":
                level = level + 1
            elif token == "DEDENT":
                level = level - 1
            if token == "group":
                 self.get_group(level)
            elif token == "ruleset":
                 self.get_ruleset(level)
            elif token == "interface":
                 self.get_interface(level)
            indent = " " * (level * 4)
            if not text or token == text:
                value = token
            else:
                value = "%s(%s)" % (token, repr(text))
        # Just for some consistancy (e.g. unittest)
        for group in self.groups.itervalues():
            group.sort()

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
                self.log_error("Cannot invert addresses")
            else:
                invert = ""
            ips = []
            try:
                ip = netaddr.IPNetwork(name)
                if ip.network != ip.ip:
                    self.log_error(FWIPMaskBoundaryError(ip).log_message())
                ips = [ip]
            except netaddr.core.AddrFormatError, e:
                if self.groups.has_key(name) and \
                   self.groups[name].lineno is not None:
                    ips = self.groups[name].ips()
                elif name.find(".") != -1:
                    hostname = Hostname(name, rule.lineno)
                    try:
                        hostname.resolve()
                        ips = hostname.ips()
                    except FWResolveError, e:
                        self.log_error(e.log_message(), e.lineno)
                else:
                    e = FWUndefinedGroup(name, rule.lineno)
                    self.log_error(e.log_message(), e.lineno)
            for ip in ips:
                ipinfo = (ip.prefixlen, ip, invert)
                if not ipinfo in all_ip:
                    all_ip.append((ip.prefixlen, ip, invert))
        all_ip.sort()
        all_ip.reverse()
        last_ip = last_invert = None
        for prefixlen, ip, invert in all_ip:
            if last_ip is not None:
                if last_ip == ip:
                    if last_invert != invert:
                        self.log_error("Conflicting definitions (%s/%s, !%s,%s)" % (addr, mask, addr, mask), rule.lineno)
                    continue
            last_ip = ip
            last_invert = invert
            for target_ip, target_invert in all_targets:
                if (
                    target_ip.size != 1
                    and (
                        (target_ip[0] >= ip[0] and target_ip[0] <= ip[-1])
                        or
                        (target_ip[-1] >= ip[0] and target_ip[1] <= ip[-1])
                        or
                        (ip[0] >= target_ip[0] and ip[0] <= target_ip[-1])
                        or
                        (ip[-1] >= target_ip[0] and ip[-1] <= target_ip[-1])
                    )
                   ):
                    self.log_warning("Overlapping ranges (%s, %s)" % (ip, target_ip), rule.lineno)
            all_targets.append((ip, invert))
            if ip.version == 4:
                all_ip4.append((invert, ip))
            elif ip.version == 6:
                all_ip6.append((invert, ip))
            else:
                self.log_error("Invalid ip version for %s" % ip)
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
                        self.log_error("Conflicting port definition", rule.lineno)
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
                self.log_error("Cannot use '!' on multiple port definitions", rule.lineno)
                return [],[]
            if p1 == p2:
                if not invert:
                    if len(all) == 1:
                        range_ports.append("%s" % p1)
                    else:
                        comma_ports.append("%s" % p1)
                else:
                    comma_ports.append("!%s" % p1)
            else:
                range_ports.append("%s%s:%s" % (invert, p1, p2))
        all = comma_ports
        comma_ports = []
        while len(all):
            comma_ports.append(",".join(all[:15]))
            del(all[:15])
        if not comma_ports and not range_ports:
            return [], [""]
        return comma_ports, range_ports

    def resolve(self):
        for group in self.groups.itervalues():
            try:
                group.resolve()
            except FWRecursion, e:
                self.log_error(e.log_message(), e.lineno)
            except FWResolveError, e:
                self.log_error(e.log_message(), e.lineno)
        for group in self.groups.itervalues():
            if group.lineno is None:
                raise FWUndefinedGroup(group.name, group.referred_lines[0])

    def make_rule(self, chainnr, chainname, iface, rule):
        if not rule:
            if self.nerrors == 0:
                self.log_error("Invalid rule in interface %s: %s" % (iface, chainname))
            return "", ""
        # Get all source ips
        srcs_ip4, srcs_ip6 = self.resolve_ip(rule.sources, rule)
        dsts_ip4, dsts_ip6 = self.resolve_ip(rule.destinations, rule)
        lines_ip4 = []
        lines_ip6 = []
        line = []
        targets = []
        if rule.nat or rule.action == "masq":
            line += ["-t nat"]
            if not srcs_ip4 or not dsts_ip4:
                self.log_error("NAT rule only valid for IPv4", rule.lineno)
            else:
                all = netaddr.IPNetwork("::/0")
                for src in srcs_ip6:
                    if src[1] != all:
                        self.log_warning("Ignoring %s rule for IPv6 source address %s" % (rule.action, src), rule.lineno)
                for dst in dsts_ip6:
                    if dst[1] != all:
                        self.log_warning("Ignoring %s rule for IPv6 destination address %s" % (rule.action, dst), rule.lineno)
        else:
            line += ["-t filter"]
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
            targets.append('LOG --log-prefix "%s " --log-level %s -m limit --limit 60/minute --limit-burst 10' % (s, rule.logging))
        if rule.direction == "in":
            line += ["-i", iface]
        elif rule.direction == "out":
            line += ["-o", iface]
        else:
            self.log_error("Invalid direction '%s'" % rule.direction, rule.lineno)
        chainname = rule.chainname(chainnr, chainname, iface)
        line += ["-p", rule.protocol]
        if rule.state:
            line += ["-m state --state", rule.state]
        line += ["-A %d%s" % (100 + chainnr, chainname)]
        if rule.nat:
            if rule.natports:
                nat = "%s:%s" % (rule.nat, rule.natports)
            else:
                nat = rule.nat
            if rule.action == "snat":
                targets.append("SNAT")
                line += ["-j %(target)s --to-source", nat]
            else:
                targets.append("DNAT")
                line += ["-j %(target)s --to-destination", nat]
        else:
            if rule.action == "permit":
                if rule.direction == "in" and \
                  not rule.local:
                    targets.append("RETURN")
                else:
                    targets.append("ACCEPT")
                line += ["-j %(target)s"]
            elif rule.action == "deny":
                targets.append("DROP")
                line += ["-j %(target)s"]
            elif rule.action == "masq":
                targets.append("MASQUERADE")
                line += ["-j %(target)s"]
        line_start = " ".join(line)
        # Get all src ports (two lists: ranges and comma sep)
        src_comma_ports, src_range_ports = self.resolve_ports(rule.srcports, rule)
        # Get all destination ips
        destinations = self.resolve_ip(rule.destinations, rule)
        # Get all dst ports (two lists: ranges and comma sep)
        dst_comma_ports, dst_range_ports = self.resolve_ports(rule.dstports, rule)
        if rule.nat:
            sources = srcs_ip4
            destinations = dsts_ip4
        else:
            sources = srcs_ip4 + srcs_ip6
            destinations = dsts_ip4 + dsts_ip6
        for src_invert, src_ip in sources:
            if src_ip.version == 4:
                lines = lines_ip4
            else:
                lines = lines_ip6
            if src_ip.prefixlen == 0:
                src = ""
            else:
                src = "--src %s%s/%s" % (src_invert, src_ip.ip, src_ip.prefixlen)
            for dst_invert, dst_ip in destinations:
                if rule.nat and src_ip.version != 4:
                    continue
                if src_ip.version != dst_ip.version:
                    continue
                if dst_ip.prefixlen == 0:
                    dst = ""
                else:
                    dst = "--dst %s%s/%s" % (dst_invert, dst_ip.ip, dst_ip.prefixlen)
                for sport in src_comma_ports:
                    for dport in dst_comma_ports:
                        for target in targets:
                            lines.append(" ".join([line_start % {"target": target}, src, "-m multiport --sports", sport, dst, "-m multiport --dports", dport]))
                    for dport in dst_range_ports:
                        if dport != "":
                            dport = "--dport %s" % dport
                        for target in targets:
                            lines.append(" ".join([line_start % {"target": target}, src, "-m multiport --sports", sport, dst, dport]))
                for sport in src_range_ports:
                    if sport != "":
                        sport = "--sport %s" % sport
                    for dport in dst_comma_ports:
                        for target in targets:
                            lines.append(" ".join([line_start % {"target": target}, src, sport, dst, "-m multiport --dports", dport]))
                    for dport in dst_range_ports:
                        if dport != "":
                            dport = "--dport %s" % dport
                        for target in targets:
                            lines.append(" ".join([line_start % {"target": target}, src, sport, dst, dport]))
        return [line.strip() for line in lines_ip4], [line.strip() for line in lines_ip6]
            

    def make_rules(self):
        chains4 = {}
        chains6 = {}
        ifaces_keys = self.ifaces.keys()
        ifaces_keys.sort()
        for iface in ifaces_keys:
            chain_idx = 0
            for chain in self.chainorder[iface]:
                chain_idx += 1
                lines_ip4 = []
                lines_ip6 = []
                filename = "fwm-%s" % chain
                i = 0
                for rule in self.ifaces[iface][chain]:
                    rule_ip4, rule_ip6 = self.make_rule(chain_idx, chain, iface, rule)
                    lines_ip4 += rule_ip4
                    lines_ip6 += rule_ip6
                if chains4.has_key(filename):
                    chains4[filename] += lines_ip4
                else:
                    chains4[filename] = lines_ip4
                if chains6.has_key(filename):
                    chains6[filename] += lines_ip6
                else:
                    chains6[filename] = lines_ip6
        return chains4, chains6

    def write_rules(self, chains4, chains6):
        if self.nerrors != 0:
            return
        for chainsdir, chains in [(self.chainsdir_ip4, chains4), (self.chainsdir_ip6, chains6)]:
            if not os.path.isdir(chainsdir):
                self.log_error("Not a directory: %s" % chainsdir)
        if self.nerrors != 0:
            return
        for chainsdir, chains in [(self.chainsdir_ip4, chains4), (self.chainsdir_ip6, chains6)]:
            chains_keys = chains.keys()
            chains_keys.sort()
            for chainname in chains_keys:
                fname = "%s/%s" % (chainsdir, chainname)
                try:
                    fp = open(fname, "w")
                    fp.write("%s\n" % "\n".join(chains[chainname]))
                    fp.close()
                except IOError, why:
                    self.log_error("Error writing file '%s': %s" % (fname, why))
            for fname in os.listdir(chainsdir):
                if fname[:4] != "fwm-":
                    continue
                if not chains.has_key(fname):
                    os.unlink("%s/%s" % (chainsdir, fname))


class FWCompile(object):

    chainsdir = None
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

    def __init__(self, 
                 remove_all_chains=False,
                 verbose=False,
                ):
        self.remove_all_chains = remove_all_chains
        self.verbose = verbose
        self.nerrors = 0
        self.nwarnings = 0
        self.newchains = {}
        self.filechains = {}
        self.reserved_chains = {}
        for table in self.tables:
            self.reserved_chains[table] = []

    def log(self, level, msg):
        sys.stderr.write("%s\n" % msg)

    def log_error(self, msg, lineno = None):
        if self.nerrors > 10:
            sys.exit(1)
        self.nerrors += 1
        if lineno is not None:
            self.log(syslog.LOG_ERR, "line %d, %s" % (lineno, msg))
            return
        self.log(syslog.LOG_ERR, "%s" % msg)

    def log_warning(self, msg, lineno = None):
        self.nwarnings += 1
        if lineno is not None:
            self.log(syslog.LOG_WARNING, "line %d, %s" % (lineno, msg))
            return
        self.log(syslog.LOG_WARNING, "%s" % msg)

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
           not parentchains[0] in self.builtin_chains[table]:
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
        except IOError, why:
            sys.stderr.write("Error reading file '%s': %s\n" % (fpath, why))
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
                fpath = "%s/%s" % (self.chainsdir, fname)
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
                            newchain = "%s%s" % (m.group(2), m.group(3))
                        else:
                            newchain = m.group(3)
                        line = line.replace("-A %s" % chain, "-A %s" % newchain)
                        chain = newchain
                    if chain in self.reserved_chains[table]:
                        raise FWReservedChainName(chain, fname, linenr)
                    if not self.filechains[fname][table].has_key(chain):
                        self.filechains[fname][table][chain] = []
                    self.filechains[fname][table][chain].append(line)
                    self.newchains[table][(num, chain)] = 1
                    if not chain in chainorder[table]:
                        chainorder[table][chain] = (num, fname, linenr)
                    elif chainorder[table][chain][0] != num:
                        raise FWOrderConflict(
                            chain, 
                            fname,
                            linenr,
                            (chainorder[table][chain]),
                        )

        for table in self.tables:
            sortchains = self.newchains[table].keys()
            sortchains.sort()
            self.newchains[table] = []
            for order, chain in sortchains:
                if not chain in self.newchains[table]:
                    self.newchains[table].append(chain)

    def generate_restore_file(self, rule_file):
        targets = {}
        rules = {}
        for table in self.tables:
            targets[table] = []
            rules[table] = []
            for chain in self.newchains[table]:
                if not table in self.tables:
                    raise FWInvalidTable(table)
                targets[table].append(chain)
                parentchains  = self.parentchains(table, chain)
                for pchain in parentchains:
                    m = self.re_chaindef.match(chain)
                    if m.group(2):
                        iface = m.group(2)[1:-1]
                        direction = m.group(2)[0].lower()
                        rules[table].append("-A %s -%s %s -j %s" % ( pchain, direction, iface, chain))
                    else:
                        rules[table].append("-A %s -j %s" % (pchain, chain))
        for table in self.tables:
            for chain in self.newchains[table]:
                for fname in self.filechains.keys():
                    if self.filechains[fname][table].has_key(chain):
                        for line in self.filechains[fname][table][chain]:
                            match = self.re_table_rule.match(line)
                            if match:
                                line = "%s %s" % (match.group(1).strip(), match.group(3).strip())
                            rules[table].append(line.strip())

        if rule_file == "-" or not rule_file:
            fp = sys.stdout
        elif hasattr(rule_file, "seek"):
            fp = rule_file
        else:
            fp = open(rule_file, "w")
        fp.write("# Generated with %s at %s\n" % (self.__class__.__name__, time.ctime(),))
        for table in self.tables:
            fp.write("*%s\n" % table)
            if self.remove_all_chains or table != "filter":
                policy = "ACCEPT"
            else:
                policy = "DROP"
            for target in self.builtin_chains[table]:
                fp.write(":%s %s [0:0]\n" % (target, policy))
            
            for target in targets[table]:
                fp.write(":%s - [0:0]\n" % target)
            for rule in rules[table]:
                fp.write("%s\n" % rule)
            fp.write("COMMIT\n")


class FWCompileIPv4(FWCompile):

    chainsdir = CHAINSDIR_IPV4
    tables = ["raw", "mangle", "nat", "filter"]


class FWCompileIPv6(FWCompile):

    chainsdir = CHAINSDIR_IPV6
    tables = ["filter", "mangle"]


def fwmpp():
    import optparse

    parser = optparse.OptionParser(
        usage="""\
usage: %%prog [options] FILE

Rule format:
%(rule_explanation)s
Defaults:
%(defaults_txt)s
ICMP options:
%(icmp_options_txt)s
""" % globals(),
    )

    parser.add_option(
        "-V", "--version",
        action="store_true",
        dest="version",
        default=False,
        help="show version and exit",
    )
    parser.add_option(
        "--ipv4-chains",
        action="store",
        dest="chainsdir_ip4",
        default=CHAINSDIR_IPV4,
        metavar="DIRECTORY",
        help="directory with iptables chains (default: %s)" % CHAINSDIR_IPV4,
    )
    parser.add_option(
        "--ipv6-chains",
        action="store",
        dest="chainsdir_ip6",
        default=CHAINSDIR_IPV6,
        metavar="DIRECTORY",
        help="directory with ip6tables chains (default: %s)" % CHAINSDIR_IPV6,
    )
    parser.add_option(
        "--logtag",
        action="store",
        dest="logtag",
        default=FWPreprocess.logtag,
        help="log tag template (default: '%s')" % FWPreprocess.logtag,
    )


    opts, args = parser.parse_args()
    if opts.version:
        print "Version: %s" % ".".join([str(i) for i in __version__])
        sys.exit(0)

    if len(args) == 0:
        args = ["-"]
    elif len(args) != 1:
        sys.stderr.write("Too many arguments")
        sys.exit(1)
    fwprepocess = FWPreprocess(args[0])
    fwprepocess.chainsdir_ip4 = opts.chainsdir_ip4
    fwprepocess.chainsdir_ip6 = opts.chainsdir_ip6
    fwprepocess.logtag = opts.logtag

    fwprepocess.read_fwrules()
    fwprepocess.resolve()
    chains4, chains6 = fwprepocess.make_rules()
    if fwprepocess.nerrors == 0:
        fwprepocess.write_rules(chains4, chains6)
    else:
        sys.stderr.write("Errors (%s)\n" % fwprepocess.nerrors)
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
        "--ipv4-rules",
        action="store",
        dest="ipv4_rules",
        default=CHAINSFILE_IPV4,
        help="filename of generated iptables-restore file",
    )
    parser.add_option(
        "--ipv6-rules",
        action="store",
        dest="ipv6_rules",
        default=CHAINSFILE_IPV6,
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
        dest="chainsdir_ip4",
        default=CHAINSDIR_IPV4,
        metavar="DIRECTORY",
        help="directory with iptables chains (default: %s)" % CHAINSDIR_IPV4,
    )
    parser.add_option(
        "--ipv6-chains",
        action="store",
        dest="chainsdir_ip6",
        default=CHAINSDIR_IPV6,
        metavar="DIRECTORY",
        help="directory with ip6tables chains (default: %s)" % CHAINSDIR_IPV6,
    )
    parser.add_option(
        "--reserved-target",
        action="append",
        dest="reserved_targets",
        default=FWCompile.reserved_targets,
        help="reserved target (e.g. ACCEPT) that will not be mapped to a chain",
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
        print "Version: %s" % ".".join([str(i) for i in __version__])
        sys.exit(0)
    if opts.help_reserved_target:
        print "Default reserved targets:"
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
                print "%s%s" % (indent, new_line)
                del(default_reserved_targets[0])
            else:
                print "%s%s" % (indent, line)
                line = ""
        sys.exit(0)

    if len(args) == 0:
        args = ["start"]
    elif len(args) != 1:
        sys.stderr.write("Too many arguments\n")
        sys.exit(1)
    if not args[0] in ["start", "stop"]:
        sys.stderr.write("Invalid argument '%s'\n" % args[0])
        sys.exit(1)

    remove_all_chains = False
    if args[0] in ["stop"]:
        remove_all_chains = 1

    if opts.ipv4:
        fwcompile = FWCompileIPv4(
            remove_all_chains = remove_all_chains,
            verbose = opts.verbose,
        )
        fwcompile.chainsdir = opts.chainsdir_ip4
        chainsfiles = os.listdir(fwcompile.chainsdir)
        try:
            fwcompile.read_chain_files(chainsfiles)
            fwcompile.generate_restore_file(opts.ipv4_rules)
        except FWMacroException, e:
            fwcompile.log_error(e.log_message())
    if opts.ipv6:
        fwcompile = FWCompileIPv6(
            remove_all_chains = remove_all_chains,
            verbose = opts.verbose,
        )
        fwcompile.chainsdir = opts.chainsdir_ip6
        chainsfiles = os.listdir(fwcompile.chainsdir)
        try:
            fwcompile.read_chain_files(chainsfiles)
            fwcompile.generate_restore_file(opts.ipv6_rules)
        except FWMacroException, e:
            fwcompile.log_error(e.log_message())
    sys.exit(0)

def main():
    progname = os.path.basename(sys.argv[0])
    if progname in ["fwmpp", "fwmpp.py"]:
        fwmpp()
    elif progname in ["fwmc", "fwmc.py"]:
        fwmc()
    else:
        sys.stderr.write("Invalid invocation as '%s'\n" % progname)
        exit(1)

if __name__ == "__main__":
    main()
