fwmacro is a library for generating iptables/ip6tables rules and to
generate input files for iptables-restore and ip6tables-restore.

The library comes with two scripts: fwmpp and fwmc

The fwmpp command processes the simplified rules to a set of
iptables/ip6tables rules and fwmc compiles a set of iptables/ip6tables rules to a
iptables-restore/ip6tables-restore file.

Typical setup/usage will be:
  * Create files with default chain sets in /etc/fwmacro/chains[4|6]/
  * Create a file with simplified rules in /etc/fwmacro/fw.rules
  * Compile these with: fwmpp /etc/fwmacro/fw.rules
  * Build restore files with: fwmc
  * Install iptables rules with: iptables-restore /etc/fwmacro/ipv4.rules
  * Install ip6tables rules with: ip6tables-restore /etc/fwmacro/ipv6.rules


For network performance reasons, the fwmpp rules are based on interface. This results in separate chains for traffic that is entering (in) or leaving (out) the interfaces.


---

The first commit of the fwmacro code is there.

The code is used in a live environment (i.e. a real full-service
server park firewall), but only ipv4 is effectively used.

The ip6tables rules are currently untested.