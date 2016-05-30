#!/usr/bin/env python

import sys
import os.path
# Make sure we'll import the fwmacro module from the
# source directory and not from the system directories
sys.path.insert(
    0,
    os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
        "..",
    )),
)

import unittest
from StringIO import StringIO
from netaddr import IPNetwork

import fwmacro
from fwmacro import *


class FWPreprocess(fwmacro.FWPreprocess):
    def __init__(self, *args, **kwargs):
        fwmacro.FWPreprocess.__init__(self, *args, **kwargs)
        self.all_errors = []
        self.all_warnings = []

    def log_error(self, msg, lineno = None):
        self.nerrors += 1
        if lineno is None:
            p = self.position()
            if p:
                lineno = p[1]
        self.all_errors.append((lineno, msg))

    def log_warning(self, msg, lineno = None):
        self.nwarnings += 1
        if lineno is None:
            p = self.position()
            if p:
                lineno = p[1]
        self.all_warnings.append((lineno, msg))


class FWMPreprocessTestCase(unittest.TestCase):
    def get_fwprepocess(self, rules):
        fp = StringIO(rules)
        fwprepocess = FWPreprocess(fp)
        fwprepocess.read_fwrules()
        return fwprepocess

    def get_chains(self, rules, permit_errors=False, permit_warnings=False):
        fwprepocess = self.get_fwprepocess(rules)
        fwprepocess.resolve()
        chains4, chains6 = fwprepocess.make_rules()
        if not permit_errors:
            if fwprepocess.all_errors:
                print fwprepocess.all_errors
            self.assertEqual(len(fwprepocess.all_errors), 0, str(fwprepocess.all_errors))
        if not permit_warnings:
            if fwprepocess.all_warnings:
                print fwprepocess.all_warnings
            self.assertEqual(len(fwprepocess.all_warnings), 0)
        return fwprepocess, chains4, chains6

    def testGroupInit(self):
        # By default the should be the group "any"
        # and only this group
        fp = StringIO("")
        fwprepocess = FWPreprocess(fp)
        self.assertEqual(len(fwprepocess.groups), 1)
        self.assertTrue("any" in fwprepocess.groups)
        self.assertEquals(
            fwprepocess.groups["any"],
            [
                IPNetwork('0.0.0.0/0'),
                IPNetwork('::/0'),
            ],
        )

    def testGroupSimple(self):
        rules = """
group foo:
    127.0.0.1

group bar:
    127.0.0.1/32
    127.0.0.0/30
    126.0.0.0/30
"""
        fwprepocess = self.get_fwprepocess(rules)
        self.assertEquals(
            fwprepocess.groups["foo"],
            [IPNetwork('127.0.0.1/32')],
        )
        self.assertEquals(
            fwprepocess.groups["bar"],
            [
                IPNetwork('126.0.0.0/30'),
                IPNetwork('127.0.0.0/30'),
                IPNetwork('127.0.0.1/32'),
            ],
        )

    def testGroupNested(self):
        rules = """
group foo:
    127.0.0.1

group bar:
    foo
    127.0.0.0/30
"""
        fwprepocess = self.get_fwprepocess(rules)
        self.assertEquals(
            fwprepocess.groups["foo"],
            [IPNetwork('127.0.0.1/32')],
        )
        self.assertEquals(
            fwprepocess.groups["bar"],
            [
                [IPNetwork('127.0.0.1/32'),],
                IPNetwork('127.0.0.0/30'),
            ],
        )

        rules = """
group bar:
    foo
    127.0.0.0/30

group foo:
    127.0.0.1
"""
        fwprepocess = self.get_fwprepocess(rules)
        self.assertEquals(
            fwprepocess.groups["foo"],
            [IPNetwork('127.0.0.1/32')],
        )
        self.assertEquals(
            fwprepocess.groups["bar"],
            [
                [IPNetwork('127.0.0.1/32'),],
                IPNetwork('127.0.0.0/30'),
            ],
        )
        self.assertFalse(
            fwprepocess.groups["foo"].resolved,
        )
        fwprepocess.resolve()
        self.assertTrue(
            fwprepocess.groups["foo"].resolved,
        )

    def testGroupUnresolved(self):
        rules = """
group bar:
    foo
    127.0.0.0/30
"""
        fwprepocess = self.get_fwprepocess(rules)
        self.assertEquals(
            fwprepocess.groups["foo"],
            [],
        )
        self.assertEquals(
            fwprepocess.groups["bar"],
            [
                [],
                IPNetwork('127.0.0.0/30'),
            ],
        )
        self.assertFalse(
            fwprepocess.groups["foo"].resolved,
        )
        try:
            fwprepocess.resolve()
        except FWUndefinedGroup, e:
            self.assertEqual(
                (e.name, e.lineno),
                ("foo", 3),
            )

    def testGroupWithHost(self):
        rules = """
group foo:
    fwmacro.googlecode.com
"""
        fwprepocess = self.get_fwprepocess(rules)
        self.assertEquals(
            fwprepocess.groups["foo"],
            [[]],
        )
        self.assertTrue(
            isinstance(fwprepocess.groups["foo"][0], Hostname)
        )
        fwprepocess.resolve()

    def testGroupNot(self):
        rules = """
group foo:
    !127.0.0.1/32
"""
        fwprepocess = self.get_fwprepocess(rules)
        self.assertEqual(
            fwprepocess.all_errors,
            [(3, "Unexpected '!'")],
        )

    def testGroupIPMaskBoundaryError(self):
        rules = """
group foo:
    127.0.0.1/30
"""
        self.assertRaises(FWIPMaskBoundaryError, self.get_chains, rules)

    def testInterfaceRule(self):
        rules = """
interface lo:
    in permit ip any any
    out permit ip any any
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules)
        self.assertEqual(
            len(fwprepocess.ifaces),
            1,
        )
        self.assertEqual(
            len(fwprepocess.ifaces["lo"]),
            1,
        )
        self.assertEqual(
            repr(fwprepocess.ifaces["lo"]["ifs"]),
            "[<Rule line: 3, local: False, direction: in, action: permit>, "
            "<Rule line: 4, local: False, direction: out, action: permit>]",
        )
        self.assertEqual(
            chains4["fwm-ifs"],
            [
                "-t filter -i lo -p all -m state --state NEW -A 101ilo:ifs -j RETURN",
                "-t filter -o lo -p all -m state --state NEW -A 101olo:ifs -j ACCEPT",
            ],
        )
        self.assertEqual(
            chains6["fwm-ifs"],
            [
                "-t filter -i lo -p all -m state --state NEW -A 101ilo:ifs -j RETURN",
                "-t filter -o lo -p all -m state --state NEW -A 101olo:ifs -j ACCEPT",
            ],
        )

    def testRuleset(self):
        rules = """
ruleset foo:
    in permit ip any any

interface lo:
    ruleset foo
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules)
        self.assertEqual(
            len(fwprepocess.rulesets),
            1,
        )
        self.assertEqual(
            repr(fwprepocess.rulesets["foo"]),
            "[<Rule line: 3, local: False, direction: in, action: permit>]",
        )
        self.assertEqual(
            chains4["fwm-ifs"],
            [
                "-t filter -i lo -p all -m state --state NEW -A 101ilo:ifs -j RETURN",
            ],
        )
        self.assertEqual(
            chains6["fwm-ifs"],
            [
                "-t filter -i lo -p all -m state --state NEW -A 101ilo:ifs -j RETURN",
            ],
        )

    def testDnat(self):
        rules = """
interface lo:
    out dnat 127.0.0.1 ip any any
    out dnat 127.0.0.1-127.0.0.2 ip any any
    out dnat 127.0.0.1-127.0.0.2 80 tcp any all any all
    out dnat 127.0.0.1-127.0.0.2 80-84 tcp any all any all
    out dnat 127.0.0.1-127.0.0.2 80 tcp any all 127.0.0.3/32 all
    out dnat 127.0.0.1-127.0.0.2 80 tcp any all any 80
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules)
        self.assertEqual(
            repr(fwprepocess.ifaces["lo"]["ifs"]),
            "[<Rule line: 3, local: False, direction: out, action: dnat>, "
            "<Rule line: 4, local: False, direction: out, action: dnat>, "
            "<Rule line: 5, local: False, direction: out, action: dnat>, "
            "<Rule line: 6, local: False, direction: out, action: dnat>, "
            "<Rule line: 7, local: False, direction: out, action: dnat>, "
            "<Rule line: 8, local: False, direction: out, action: dnat>]",
        )
        self.assertEqual(
            chains4["fwm-ifs"],
            [
                "-t nat -o lo -p all -m state --state NEW -A 101olo:ifs -j DNAT --to-destination 127.0.0.1", 
                "-t nat -o lo -p all -m state --state NEW -A 101olo:ifs -j DNAT --to-destination 127.0.0.1-127.0.0.2",
                "-t nat -o lo -p tcp -m state --state NEW -A 101olo:ifs -j DNAT --to-destination 127.0.0.1-127.0.0.2:80",
                "-t nat -o lo -p tcp -m state --state NEW -A 101olo:ifs -j DNAT --to-destination 127.0.0.1-127.0.0.2:80-84",
                "-t nat -o lo -p tcp -m state --state NEW -A 101olo:ifs -j DNAT --to-destination 127.0.0.1-127.0.0.2:80   --dst 127.0.0.3/32",
                "-t nat -o lo -p tcp -m state --state NEW -A 101olo:ifs -j DNAT --to-destination 127.0.0.1-127.0.0.2:80    --dport 80",
            ],
        )
        self.assertEqual(
            chains6["fwm-ifs"],
            []
        )

    def testSnat(self):
        rules = """
interface lo:
    out snat 127.0.0.1 ip any any
    out snat 127.0.0.1-127.0.0.2 ip any any
    out snat 127.0.0.1-127.0.0.2 80 tcp any all any all
    out snat 127.0.0.1-127.0.0.2 80-84 tcp any all any all
    out snat 127.0.0.1-127.0.0.2 80 tcp 127.0.0.3/32 all any all
    out snat 127.0.0.1-127.0.0.2 80 tcp any 80 any all
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules)
        self.assertEqual(
            repr(fwprepocess.ifaces["lo"]["ifs"]),
            "[<Rule line: 3, local: False, direction: out, action: snat>, "
            "<Rule line: 4, local: False, direction: out, action: snat>, "
            "<Rule line: 5, local: False, direction: out, action: snat>, "
            "<Rule line: 6, local: False, direction: out, action: snat>, "
            "<Rule line: 7, local: False, direction: out, action: snat>, "
            "<Rule line: 8, local: False, direction: out, action: snat>]",
        )
        self.assertEqual(
            chains4["fwm-ifs"],
            [
                "-t nat -o lo -p all -m state --state NEW -A 101olo:ifs -j SNAT --to-source 127.0.0.1",
                "-t nat -o lo -p all -m state --state NEW -A 101olo:ifs -j SNAT --to-source 127.0.0.1-127.0.0.2",
                "-t nat -o lo -p tcp -m state --state NEW -A 101olo:ifs -j SNAT --to-source 127.0.0.1-127.0.0.2:80",
                "-t nat -o lo -p tcp -m state --state NEW -A 101olo:ifs -j SNAT --to-source 127.0.0.1-127.0.0.2:80-84",
                "-t nat -o lo -p tcp -m state --state NEW -A 101olo:ifs -j SNAT --to-source 127.0.0.1-127.0.0.2:80 --src 127.0.0.3/32",
                "-t nat -o lo -p tcp -m state --state NEW -A 101olo:ifs -j SNAT --to-source 127.0.0.1-127.0.0.2:80  --sport 80",
            ],
        )
        self.assertEqual(
            chains6["fwm-ifs"],
            []
        )

    def testDnatErrors(self):
        rules = """
interface lo:
    out dnat 129.0.0.1 80 ip any any
    out dnat 128.0.0.1 ip ::/0 ::/0
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules, permit_errors=True)
        self.assertEqual(
            fwprepocess.all_errors,
            [
                (3, "Ports not used in nat definition (use tcp or udp match condition)"),
                (4, "NAT rule only valid for IPv4"),
            ],
        )

    def testMasq(self):
        rules = """
ruleset uplink:
    out masq NONE ip 192.168.0.0/24 any

interface eth0:
    ruleset uplink
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules, permit_errors=True)
        self.assertEqual(
            chains4["fwm-ifs"],
            [
                "-t nat -o eth0 -p all -A 101oeth0:ifs -j MASQUERADE --src 192.168.0.0/24",
            ],
        )

    def testIPv6GroupSimple(self):
        rules = """
group foo:
    2001:470:15:80::2/128

group bar:
    2001:470:15::/64
    2001:470:15::/63
    2001:470:14::/63
"""
        fwprepocess = self.get_fwprepocess(rules)
        self.assertEquals(
            fwprepocess.groups["foo"],
            [
                IPNetwork('2001:470:15:80::2/128'),
            ],
        )
        self.assertEquals(
            fwprepocess.groups["bar"],
            [
                IPNetwork('2001:470:14::/63'), 
                IPNetwork('2001:470:15::/63'), 
                IPNetwork('2001:470:15::/64'),
            ],
        )

    def testIPv6GroupIPMaskBoundaryError(self):
        rules = """
group foo:
    2001:470:15:80::1/126
"""
        self.assertRaises(FWIPMaskBoundaryError, self.get_chains, rules)

    def testProtocolNumber(self):
        rules = """
interface eth0:
    in permit 41 any any
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules)
        self.assertEquals(
            chains4["fwm-ifs"],
            [
                '-t filter -i eth0 -p 41 -m state --state NEW -A 101ieth0:ifs -j RETURN',
            ],
        )
    def testProtocolName(self):
        rules = """
interface eth0:
    in permit igmp any any
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules)
        self.assertEquals(
            chains4["fwm-ifs"],
            [
                '-t filter -i eth0 -p 2 -m state --state NEW -A 101ieth0:ifs -j RETURN',
            ],
        )
        self.assertEquals(
            chains6["fwm-ifs"],
            [
                '-t filter -i eth0 -p 2 -m state --state NEW -A 101ieth0:ifs -j RETURN',
            ],
        )

    def testProtocolIcmp(self):
        rules = """
interface eth0:
    out permit icmp any any
    in permit icmp 1.2.3.4/32 5.6.7.8/32
    in permit icmp 0 1.2.3.4/32 5.6.7.8/32
    in permit icmp echo-reply 1.2.3.4/32 5.6.7.8/32
    in permit icmp 3/0 1.2.3.4/32 5.6.7.8/32
    in permit icmp network-unreachable 1.2.3.4/32 5.6.7.8/32
    in permit icmp 2001:470:15:80::3/128 2001:470:15:80::4/128
    in permit icmp 0 2001:470:15:80::3/128 2001:470:15:80::4/128
    in permit icmp echo-reply 2001:470:15:80::3/128 2001:470:15:80::4/128
    in permit icmp 3/0 2001:470:15:80::3/128 2001:470:15:80::4/128
    in permit icmp communication-prohibited 2001:470:15:80::3/128 2001:470:15:80::4/128
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules)
        self.assertEquals(
            chains4["fwm-ifs"],
            [
                '-t filter -o eth0 -p icmp -m state --state NEW -A 101oeth0:ifs -j ACCEPT',
                '-t filter -i eth0 -p icmp -m state --state NEW -A 101ieth0:ifs -j RETURN --src 1.2.3.4/32  --dst 5.6.7.8/32',
                '-t filter -i eth0 -p icmp --icmp-type 0 -m state --state NEW -A 101ieth0:ifs -j RETURN --src 1.2.3.4/32  --dst 5.6.7.8/32',
                '-t filter -i eth0 -p icmp --icmp-type echo-reply -m state --state NEW -A 101ieth0:ifs -j RETURN --src 1.2.3.4/32  --dst 5.6.7.8/32',
                '-t filter -i eth0 -p icmp --icmp-type 3/0 -m state --state NEW -A 101ieth0:ifs -j RETURN --src 1.2.3.4/32  --dst 5.6.7.8/32',
                '-t filter -i eth0 -p icmp --icmp-type network-unreachable -m state --state NEW -A 101ieth0:ifs -j RETURN --src 1.2.3.4/32  --dst 5.6.7.8/32',
            ],
        )
        self.assertEquals(
            chains6["fwm-ifs"],
            [
                '-t filter -o eth0 -p icmpv6 -A 101oeth0:ifs -j ACCEPT',
                '-t filter -i eth0 -p icmpv6 -A 101ieth0:ifs -j RETURN --src 2001:470:15:80::3/128  --dst 2001:470:15:80::4/128',
                '-t filter -i eth0 -p icmpv6 --icmpv6-type 0 -A 101ieth0:ifs -j RETURN --src 2001:470:15:80::3/128  --dst 2001:470:15:80::4/128',
                '-t filter -i eth0 -p icmpv6 --icmpv6-type echo-reply -A 101ieth0:ifs -j RETURN --src 2001:470:15:80::3/128  --dst 2001:470:15:80::4/128',
                '-t filter -i eth0 -p icmpv6 --icmpv6-type 3/0 -A 101ieth0:ifs -j RETURN --src 2001:470:15:80::3/128  --dst 2001:470:15:80::4/128',
                '-t filter -i eth0 -p icmpv6 --icmpv6-type communication-prohibited -A 101ieth0:ifs -j RETURN --src 2001:470:15:80::3/128  --dst 2001:470:15:80::4/128',
            ],
        )

    def testExampleSyntax(self):
        # Test the example from
        # http://code.google.com/p/fwmacro/wiki/Syntax_fwmpp
        rules = """
group localhost:
    127.0.0.1

group staff:
    1.2.3.4/30
    1.2.3.10/32

ruleset no_localhost:
    local in deny ip localhost any
    in deny ip localhost any

interface eth0:
    ruleset no_localhost
    # rules to/from the interface itself start with "local"
    # Permit access from staff to ssh port (only the ip addresses bound to eth0)
    local in permit tcp staff all any 22
    local in deny ip any any log
    local out permit ip any any
    # rules passing the interface (i.e. in FORWARD chain)
    in permit ip any any log
    out permit ip any any
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules)
        self.assertEqual(
            chains4["fwm-ifs"],
            [
                '-t filter -i eth0 -p all -m state --state NEW -A 101Ieth0:ifs -j DROP --src 127.0.0.1/32',
                '-t filter -i eth0 -p all -m state --state NEW -A 101ieth0:ifs -j DROP --src 127.0.0.1/32',
                '-t filter -i eth0 -p tcp -m state --state NEW -A 101Ieth0:ifs -j ACCEPT --src 1.2.3.10/32   --dport 22',
                '-t filter -i eth0 -p tcp -m state --state NEW -A 101Ieth0:ifs -j ACCEPT --src 1.2.3.4/30   --dport 22',
                '-t filter -i eth0 -p all -m state --state NEW -A 101Ieth0:ifs -j LOG --log-prefix "eth0-ifs-18-deny " --log-level warning -m limit --limit 60/minute --limit-burst 10',
                '-t filter -i eth0 -p all -m state --state NEW -A 101Ieth0:ifs -j DROP',
                '-t filter -o eth0 -p all -m state --state NEW -A 101Oeth0:ifs -j ACCEPT',
                '-t filter -i eth0 -p all -m state --state NEW -A 101ieth0:ifs -j LOG --log-prefix "eth0-ifs-21-permit " --log-level warning -m limit --limit 60/minute --limit-burst 10',
                '-t filter -i eth0 -p all -m state --state NEW -A 101ieth0:ifs -j RETURN',
                '-t filter -o eth0 -p all -m state --state NEW -A 101oeth0:ifs -j ACCEPT'
            ],
        )

    def testExampleManFwmpp(self):
        # Test the example from the fwmpp manual
        rules = """
group search_engines:
    google.com
    yahoo.com

ruleset search_engines:
    out permit tcp any all search_engines 80

interface lo:
    # Permit anything to loopback interfice
    local in permit ip any any
    local out permit ip any any

interface eth0:
    local out permit tcp any all search_engines 80
    ruleset search_engines
    local out permit ip any any
    local in deny ip any any log
    # The rest is denied and logged
    in deny ip any any log
    out deny ip any any log
"""
        fwprepocess, chains4, chains6 = self.get_chains(rules)
        google = Hostname('google.com', None).resolve()
        yahoo = Hostname('yahoo.com', None).resolve()
        expected = []
        ips = google[0] + yahoo[0]
        for ip in ips:
            expected.append(
                '''-t filter -o eth0 -p tcp -m state --state NEW -A 101Oeth0:ifs -j ACCEPT   --dst %s --dport 80''' % ip
            )
            expected.append(
                '''-t filter -o eth0 -p tcp -m state --state NEW -A 101oeth0:ifs -j ACCEPT   --dst %s --dport 80''' % ip
            )
        expected.sort()
        chains4_sorted = chains4["fwm-ifs"][:2*len(ips)]
        chains4_sorted.sort()
        self.assertEqual(chains4_sorted, expected)
        self.assertEqual(
            chains4["fwm-ifs"][2*len(ips):],
            [
                '-t filter -o eth0 -p all -m state --state NEW -A 101Oeth0:ifs -j ACCEPT',
                '-t filter -i eth0 -p all -m state --state NEW -A 101Ieth0:ifs -j LOG --log-prefix "eth0-ifs-18-deny " --log-level warning -m limit --limit 60/minute --limit-burst 10',
                '-t filter -i eth0 -p all -m state --state NEW -A 101Ieth0:ifs -j DROP',
                '-t filter -i eth0 -p all -m state --state NEW -A 101ieth0:ifs -j LOG --log-prefix "eth0-ifs-20-deny " --log-level warning -m limit --limit 60/minute --limit-burst 10',
                '-t filter -i eth0 -p all -m state --state NEW -A 101ieth0:ifs -j DROP',
                '-t filter -o eth0 -p all -m state --state NEW -A 101oeth0:ifs -j LOG --log-prefix "eth0-ifs-21-deny " --log-level warning -m limit --limit 60/minute --limit-burst 10',
                '-t filter -o eth0 -p all -m state --state NEW -A 101oeth0:ifs -j DROP',
                '-t filter -i lo -p all -m state --state NEW -A 101Ilo:ifs -j ACCEPT',
                '-t filter -o lo -p all -m state --state NEW -A 101Olo:ifs -j ACCEPT'
            ],
        )


if __name__ == '__main__':
    unittest.main()

