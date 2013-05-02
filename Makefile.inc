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
PREFIX		:= /usr/local
SBINDIR		:= $(PREFIX)/sbin
MANDIR		:= $(PREFIX)/share/man
