ARCH ?= $(shell uname -m | sed          \
                -e s/i.86/x86/          \
                -e s/x86_64/x86/        \
                -e s/sun4u/sparc64/     \
                -e s/arm.*/arm/         \
                -e s/sa110/arm/         \
                -e s/s390x/s390/        \
                -e s/parisc64/parisc/   \
                -e s/ppc64.*/ppc64/     \
                -e s/mips.*/mips/       \
                -e s/sh[234].*/sh/      \
                -e s/aarch64.*/arm64/)

ifeq ($(ARCH),arm64)
        ARCH		?= aarch64
        SRCARCH		?= aarch64
endif

SRCARCH ?= $(ARCH)

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
