
all:
	dpkg-buildpackage -rfakeroot -uc -b
	dpkg-deb -c ../python-fwmacro_0.9.5_all.deb

clean:
	fakeroot debian/rules clean
	rm -f *-stamp
