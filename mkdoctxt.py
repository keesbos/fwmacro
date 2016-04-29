#!/usr/bin/env python

import sys
import fwmacro

rule_syntax = "\n".join(
    [" %s" % line for line in fwmacro.rule_explanation.split("\n")],
)
rule_defaults = "\n".join(
    [" %s" % line for line in fwmacro.rule_defaults_txt.split("\n")],
)
log_tag = fwmacro.FWPreprocess.logtag
chains4_dir = fwmacro.CHAINSDIR_IPV4
chains6_dir = fwmacro.CHAINSDIR_IPV6
ipv4_rules = fwmacro.CHAINSFILE_IPV4
ipv6_rules = fwmacro.CHAINSFILE_IPV6

for fname in sys.argv[1:]:
    if fname[-3:] != ".in":
        raise ValueError("filename must end on .in")
    data = open(fname).read()
    data = data.replace("@RULE SYNTAX@", rule_syntax)
    data = data.replace("@RULE DEFAULTS@", rule_syntax)
    data = data.replace("@LOG TAG@", log_tag)
    data = data.replace("@CHAINS4 DIR@", chains4_dir)
    data = data.replace("@CHAINS6 DIR@", chains6_dir)
    data = data.replace("@IPV4 RULES@", ipv4_rules)
    data = data.replace("@IPV6 RULES@", ipv6_rules)

    open(fname[:-3], "w").write(
        data
    )
