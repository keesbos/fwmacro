# Introduction #

Short description of the syntax used in fwmpp.


# Rule definition #
```
DIRECTION ACTION STATES PROTOCOL OPTIONS SOURCE DESTINATION LOG [LOGLEVEL] [LOGNAME]

DIRECTION   := ["local"] "in" | "out"
ACTION      := "permit" | "deny" | "snat" NATARGS | "dnat" NATARGS
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
```


# Example #
```
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
```