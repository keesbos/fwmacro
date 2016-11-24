
all:
	python setup.py bdist_egg

	./scripts/fwmc --ipv4-chains=etc/fwmacro --ipv6-chains=etc/fwmacro --ipv4-rules=etc/fwmacro/ipv4stop.rules --ipv6-rules=etc/fwmacro/ipv6stop.rules stop
	./mkdoctxt.py docs/fwmpp.txt.in docs/fwmc.txt.in
	a2x --doctype=manpage --format=manpage docs/fwmpp.txt
	a2x --doctype=manpage --format=manpage docs/fwmc.txt

clean:
	rm -rf build dist
	find docs/ ! -name \*.in -exec rm -f {} \;
	find . -name \*.pyc -exec rm {} \;
	rm -f etc/fwmacro/ipv*stop.rules
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
	twine upload dist/fwmacro-0.9.6-py2.7.egg 
