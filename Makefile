
all:
	python setup.py bdist_egg

	./scripts/fwmc --ipv4-chains=etc/fwmacro --ipv6-chains=etc/fwmacro --ipv4-rules=etc/fwmacro/ipv4stop.rules --ipv6-rules=etc/fwmacro/ipv6stop.rules stop
	./mkfwmpptxt.py
	a2x --doctype=manpage --format=manpage docs/fwmpp.txt
	a2x --doctype=manpage --format=manpage docs/fwmc.txt

clean:
	rm -rf build dist
	rm -f docs/fwmc.8 docs/fwmpp.8
	rm -f docs/fwmc.html docs/fwmpp.html
	rm -f docs/fwmc.xml docs/fwmpp.xml
	rm -f docs/fwmpp.txt
	find . -name \*.pyc -exec rm {} \;
	rm -f etc/fwmacro/ipv4stop.rules
	rm -f etc/fwmacro/ipv6stop.rules
	rm -rf fwmacro.egg-info

install:
	@echo "See INSTALL file"

uninstall:
	@echo "See INSTALL file"

tests:
	( PYTHONPATH=`pwd`; unittest/testfwpp.py )
	( PYTHONPATH=`pwd`; unittest/testfwc.py )

deb:
	( cd distro/deb ; make )

deb-clean:
	( cd distro/deb ; make clean )
	rm -f distro/python-fwmacro_*.deb
	rm -f distro/python-fwmacro_*.changes

pypi-upload: all
	python setup.py bdist_egg upload
	python setup.py sdist upload
