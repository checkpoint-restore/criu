# Silent make rules

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif

export E Q

# Installation paths
PREFIX		?= /usr/local
SBINDIR		?= $(PREFIX)/sbin
MANDIR		?= $(PREFIX)/share/man
SYSTEMDUNITDIR	?= $(PREFIX)/lib/systemd/system/
LOGROTATEDIR	?= $(PREFIX)/etc/logrotate.d/
LIBDIR		?= $(PREFIX)/lib
# For recent Debian/Ubuntu with multiarch support
DEB_HOST_MULTIARCH ?= $(shell dpkg-architecture \
			-qDEB_HOST_MULTIARCH 2>/dev/null)
ifneq "$(DEB_HOST_MULTIARCH)" ""
LIBDIR		?= $(PREFIX)/lib/$(DEB_HOST_MULTIARCH)
# For most other systems
else ifeq "$(shell uname -m)" "x86_64"
LIBDIR		?= $(PREFIX)/lib64
endif

INCLUDEDIR	?= $(PREFIX)/include/criu
