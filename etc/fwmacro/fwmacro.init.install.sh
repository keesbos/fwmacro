#!/bin/sh

# Install on debian derivates

set -e

INITSCRIPT=/etc/fwmacro/fwmacro.init

if [ ! -f ${INITSCRIPT} ] ; then
	echo "Cannot find ${INITSCRIPT}" >&2
	exit 1
fi

if [ -d /etc/init.d ] ; then
	echo "Installing ${INITSCRIPT} in /etc/init.d"
	cp ${INITSCRIPT} /etc/init.d/
	if test -x /sbin/insserv ; then
		/sbin/insserv fwmacro
	else
		update-rc.d fwmacro start 39 S . stop 39 1 .
	fi
fi
exit 0
