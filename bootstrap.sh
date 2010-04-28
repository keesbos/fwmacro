#!/bin/bash
# Bootstrap script for development
#

getYesNo ( ) {
    prompt="$1"
    case $2 in
        Y|y)
            opts="Y/n"
            default_answer=Y
            ;;
        N|n)
            opts="y/N"
            default_answer=N
            ;;
        *)
            opts="y/n"
            default_answer=
            ;;
    esac
    while true ; do
        read -e -p "$prompt [$opts] " answer
        if [ -z $answer ] ; then
            answer=$default_answer
        fi
        case $answer in
            Y*|y*)
                return 0
                ;;
            N*|n*)
                return 1
                ;;
        esac
    done
}

if [ ! -d python ] ; then
    if ! getYesNo "Create python environment?" "Y" ; then
        exit 1
    fi
    virtualenv python
fi
. python/bin/activate
easy_install plex
easy_install netaddr
