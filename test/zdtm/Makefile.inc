ARCH ?= $(shell uname -m | sed		\
		-e s/i.86/i386/		\
		-e s/sun4u/sparc64/	\
		-e s/arm.*/arm/		\
		-e s/sa110/arm/		\
		-e s/s390x/s390/	\
		-e s/parisc64/parisc/	\
		-e s/mips.*/mips/	\
		-e s/sh[234].*/sh/)

SRCARCH := $(ARCH)

ifeq ($(ARCH),i386)
	SRCARCH := x86
endif

ifeq ($(ARCH),x86_64)
	SRCARCH := x86
endif

#
# The PowerPC 64 bits architecture could be big or little endian.
# They are handled in the same way.
#
ifeq ($(shell echo $(ARCH) | sed -e 's/ppc64.*/ppc64/'),ppc64)
	ifeq ($(ARCH),ppc64)
		error	:= $(error ppc64 big endian not yet supported)
	endif
	SRCARCH	:= ppc64
endif

CPPFLAGS += -iquote $(LIBDIR)/arch/$(SRCARCH)/include

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif

RM := rm -f --one-file-system

export E Q RM
