
from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="fwmacro",
    version="0.9.6",
    description="Firewall macro compiler",
    long_description=long_description,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: System :: Operating System",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    keywords=[
        "Networking",
        "Systems Administration",
        "Firewall",
        "iptables",
        "ip6tables",
    ],
    author="Kees Bos",
    author_email="k.bos@capitar.com",
    url="https://github.com/keesbos/fwmacro",
    license="MIT",
    py_modules=["fwmacro"],
    packages=[],
    install_requires=[
        "netaddr",
        "netifaces",
    ],
    entry_points={
        "console_scripts": [
            "fwmpp=fwmacro:fwmpp",
            "fwmc=fwmacro:fwmc",
        ]
    },
    data_files=[
        ("/etc/fwmacro", [
            "etc/fwmacro/Makefile",
            "etc/fwmacro/ipv4stop.rules",
            "etc/fwmacro/ipv6stop.rules",
            "etc/fwmacro/fw.rules.sample",
            "etc/fwmacro/commit.sh.sample",
            "etc/fwmacro/fwmacro.init",
            "etc/fwmacro/fwmacro.init.install.sh",
        ]),
        ("/etc/fwmacro/chains4", [
            "etc/fwmacro/chains4/default",
        ]),
        ("/etc/fwmacro/chains6", [
            "etc/fwmacro/chains6/default",
        ]),
    ]
)
