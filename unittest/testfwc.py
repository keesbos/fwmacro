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

class FWCompileIPv4(fwmacro.FWCompileIPv4):
    def __init__(self, chain_file_data, *args, **kwargs):
        fwmacro.FWCompileIPv4.__init__(self, *args, **kwargs)
        self.chain_file_data = chain_file_data

    def read_chain_file(self, fpath):
        fpath = fpath[len(self.chainsdir)+1:]
        return self.chain_file_data[fpath]

class FWMCompileTestCase(unittest.TestCase):
    def get_fwcompile(self, cls, chain_file_data, *args, **kwargs):
        fwcompile = cls(
            chain_file_data, *args, **kwargs
        )
        return fwcompile

    def get_restore_lines(self, cls, chain_file_data, *args, **kwargs):
        fwcompile = self.get_fwcompile(cls, chain_file_data, *args, **kwargs)
        fwcompile.read_chain_files(chain_file_data.keys())
        restore_file = StringIO()
        fwcompile.generate_restore_file(restore_file)
        lines = restore_file.getvalue().strip().split("\n")
        return lines

    def testClearAll(self):
        chain_file_data = {}
        lines = self.get_restore_lines(
            FWCompileIPv4,
            chain_file_data,
            remove_all_chains = True,
        )
        self.assertEqual(len(lines), 22)
        self.assertTrue(lines[0][0] == "#")
        self.assertEqual(
            lines[1:],
            [
                "*raw",
                ":PREROUTING ACCEPT [0:0]",
                ":OUTPUT ACCEPT [0:0]",
                "COMMIT",
                "*mangle",
                ":INPUT ACCEPT [0:0]",
                ":OUTPUT ACCEPT [0:0]",
                ":FORWARD ACCEPT [0:0]",
                ":PREROUTING ACCEPT [0:0]",
                ":POSTROUTING ACCEPT [0:0]",
                "COMMIT",
                "*nat",
                ":PREROUTING ACCEPT [0:0]",
                ":POSTROUTING ACCEPT [0:0]",
                ":OUTPUT ACCEPT [0:0]",
                "COMMIT",
                "*filter",
                ":INPUT ACCEPT [0:0]",
                ":OUTPUT ACCEPT [0:0]",
                ":FORWARD ACCEPT [0:0]",
                "COMMIT",
            ],
        )

    def testDefault(self):
        chain_file_data = dict(
            a = """\
-A 10stateful -mstate --state ESTABLISHED,RELATED -j ACCEPT
-A 10stateful -mstate --state INVALID -j DROP
""",
        )
        lines = self.get_restore_lines(
            FWCompileIPv4,
            chain_file_data,
        )
        self.assertEqual(len(lines), 28)
        self.assertTrue(lines[0][0] == "#")
        self.assertEqual(
            lines[1:],
            [
                '*raw',
                ':PREROUTING ACCEPT [0:0]',
                ':OUTPUT ACCEPT [0:0]',
                'COMMIT',
                '*mangle',
                ':INPUT ACCEPT [0:0]',
                ':OUTPUT ACCEPT [0:0]',
                ':FORWARD ACCEPT [0:0]',
                ':PREROUTING ACCEPT [0:0]',
                ':POSTROUTING ACCEPT [0:0]',
                'COMMIT',
                '*nat',
                ':PREROUTING ACCEPT [0:0]',
                ':POSTROUTING ACCEPT [0:0]',
                ':OUTPUT ACCEPT [0:0]',
                'COMMIT',
                '*filter',
                ':INPUT DROP [0:0]',
                ':OUTPUT DROP [0:0]',
                ':FORWARD DROP [0:0]',
                ':stateful - [0:0]',
                '-A INPUT -j stateful',
                '-A OUTPUT -j stateful',
                '-A FORWARD -j stateful',
                '-A stateful -mstate --state ESTABLISHED,RELATED -j ACCEPT',
                '-A stateful -mstate --state INVALID -j DROP',
                'COMMIT',
            ],
        )

    def testChainOrder(self):
        # 10IN-vrrp2 should com before 11IN-vrrp1
        chain_file_data = dict(
            file1 = """
-A 11IN-vrrp1 -p all -m state --state NEW -j ACCEPT --dst 224.0.0.18/32
""",
            file2 = """
-A 10OUT-vrrp1 -p all -m state --state NEW -j ACCEPT --dst 224.0.0.18/32
""",
            file3 = """
-A 10IN-vrrp2 -p all -m state --state NEW -j ACCEPT --dst 224.0.0.5/32
""",
            file4 = """
-A 10OUT-vrrp2 -p all -m state --state NEW -j ACCEPT --dst 224.0.0.5/32
""",
        )
        lines = self.get_restore_lines(
            FWCompileIPv4,
            chain_file_data,
        )
        self.assertTrue(lines[0][0] == "#")
        self.assertEqual(
            lines[1:],
            [
                '*raw',
                ':PREROUTING ACCEPT [0:0]',
                ':OUTPUT ACCEPT [0:0]',
                'COMMIT',
                '*mangle',
                ':INPUT ACCEPT [0:0]',
                ':OUTPUT ACCEPT [0:0]',
                ':FORWARD ACCEPT [0:0]',
                ':PREROUTING ACCEPT [0:0]',
                ':POSTROUTING ACCEPT [0:0]',
                'COMMIT',
                '*nat',
                ':PREROUTING ACCEPT [0:0]',
                ':POSTROUTING ACCEPT [0:0]',
                ':OUTPUT ACCEPT [0:0]',
                'COMMIT',
                '*filter',
                ':INPUT DROP [0:0]',
                ':OUTPUT DROP [0:0]',
                ':FORWARD DROP [0:0]',
                ':IN-vrrp2 - [0:0]',
                ':OUT-vrrp1 - [0:0]',
                ':OUT-vrrp2 - [0:0]',
                ':IN-vrrp1 - [0:0]',
                '-A INPUT -j IN-vrrp2',
                '-A OUTPUT -j OUT-vrrp1',
                '-A OUTPUT -j OUT-vrrp2',
                '-A INPUT -j IN-vrrp1',
                '-A IN-vrrp2 -p all -m state --state NEW -j ACCEPT --dst 224.0.0.5/32',
                '-A OUT-vrrp1 -p all -m state --state NEW -j ACCEPT --dst 224.0.0.18/32',
                '-A OUT-vrrp2 -p all -m state --state NEW -j ACCEPT --dst 224.0.0.5/32',
                '-A IN-vrrp1 -p all -m state --state NEW -j ACCEPT --dst 224.0.0.18/32',
                'COMMIT',
            ],
        )


if __name__ == '__main__':
    unittest.main()
