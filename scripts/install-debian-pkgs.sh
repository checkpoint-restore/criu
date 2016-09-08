#!/bin/bash
# Install required packages for development environment in Debian Distro

REQ_PKGS=${REQ_PKGS:=contrib/debian/dev-packages.lst}

help_msg="Install required packages for development environment in Debian Distro
Usage:
	scripts/install-debian-pkgs.sh"

function print_help()
{
	exec echo -e "$help_msg"
}

function process()
{
	sudo apt-get update
	sudo apt-get install -yq $( sed 's/\#.*$//' ${REQ_PKGS} )
}

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
	print_help
else
	process
fi
