# Makefile for fwmacro

REMOTE=cfgsync

all: .preprocess .compile

.preprocess: fw.rules
	fwmpp fw.rules
	@touch .preprocess

.compile: chains4/* chains6/*
	fwmc
# Optionally commit rules to subversion
# or some other repository
	@-if [ -f commit.sh ] ; then \
		./commit.sh ;\
	fi
	@touch .compile

stop:
	fwmc stop
	@-rm .compile

update:
#       To force preprocessing/compiling:
#       touch fw.rules
#       To retrieve config from subversion:
#       svn update
	@echo
	@echo Pulling changes on `uname -n` from $(REMOTE)
	@-git pull ssh://$(REMOTE)/etc/fwmacro master &> /dev/null

install-ipv4: ipv4.rules
	sudo iptables-restore ipv4.rules

install-ipv6: ipv6.rules
	sudo ip6tables-restore ipv6.rules

install: .preprocess .compile install-ipv4 install-ipv6

sync:
	ssh -A $(REMOTE) "cd /etc/fwmacro;make update;make install"
