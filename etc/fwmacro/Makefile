# Makefile for fwmacro

REMOTE=
FWMPPOPTS=--force-groups

all: ipv4.rules ipv6.rules

chains4/fwm-ifs chains6/fwm-ifs: fw.rules
	fwmpp $(FWMPPOPTS) fw.rules

ipv4.rules ipv6.rules: chains4/* chains6/*
	fwmc
# Optionally commit rules to subversion
# or some other repository
	@-if [ -f commit.sh ] ; then \
		./commit.sh ;\
	fi

stop:
	fwmc stop

update:
#	To force preprocessing/compiling:
#	touch fw.rules
#	To retrieve config from subversion:
#	svn update
	@-if [ -z "$(REMOTE)" ] ;then \
		echo "No synchronization: remote undefined" ;\
	else \
		echo Pulling changes on `uname -n` from $(REMOTE) ;\
		git pull ssh://$(REMOTE)/etc/fwmacro master &> /dev/null ;\
	fi

force-compile:
	fwmpp $(FWMPPOPTS) fw.rules
	fwmc

force-install:
	@-sudo iptables-restore ipv4.rules
	@-echo "Installed ipv4.rules"
	@-sudo ip6tables-restore ipv6.rules
	@-echo "Installed ipv6.rules"

.install: ipv4.rules ipv6.rules
	@-make force-install
	@-if [ -n "$(REMOTE)" ] ; then \
		ssh -A $(REMOTE) "cd /etc/fwmacro;make update;make force-install" ;\
	fi
	@touch .install

install: .install
