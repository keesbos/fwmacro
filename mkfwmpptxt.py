#!/usr/bin/env python

import fwmacro
data = open("docs/fwmpp.txt.in").read()

rule_syntax = "\n".join(
    [ " %s" % line for line in fwmacro.rule_explanation.split("\n") ],
)

open("docs/fwmpp.txt", "w").write(
    data.replace("@RULE SYNTAX@", rule_syntax),
)
