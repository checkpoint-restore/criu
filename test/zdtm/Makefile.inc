.SUFFIXES:
MAKEFLAGS	+= -r

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

ifeq ($(ARCH),arm)
	ARMV := $(shell echo $(UNAME-M) | sed -nr 's/armv([[:digit:]]).*/\1/p; t; i7')

	ifeq ($(ARMV),6)
		USERCFLAGS += -march=armv6
	else ifeq ($(ARMV),7)
		USERCFLAGS += -march=armv7-a
	endif
endif

CC	:= gcc
CFLAGS	+= -g -O2 -Wall -Werror -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
CFLAGS	+= $(USERCFLAGS)
CFLAGS	+= -D_GNU_SOURCE
CPPFLAGS += -iquote $(LIBDIR)/arch/$(SRCARCH)/include

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif

RM := rm -f --one-file-system

ifeq ($(COMPAT_TEST),y)
ifeq ($(ARCH),x86)
        export CFLAGS += -m32
        export LDFLAGS += -m32
endif
endif

%.d: %.c
	$(E) " DEP      " $@
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -MM -MP -c $< -o $@

%.o: %.c | %.d
	$(E) " CC       " $@
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

%: %.o $(LDLIBS)
	@echo $@ >> .gitignore
	$(E) " LINK     " $@
	$(Q)$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

default: all
	@true
.PHONY: default

gitignore-clean:
	$(RM) .gitignore
.PHONY: gitignore-clean

clean: gitignore-clean
	$(RM) $(OBJ) $(TST) *~
.PHONY: clean

cleandep: clean
	$(RM) $(DEP)
.PHONY: cleandep

cleanout:
	$(RM) -r *.pid *.out* *.test* *.state
.PHONY: cleanout

%.cleanout: %
	$(Q) $(RM) -r $<.pid* $<.out* *$<.test* $<.*.test $<.*.state $<.state chew_$<.test*

realclean: cleandep cleanout
.PHONY: realclean

dep: $(DEP)
.PHONY: dep

no-deps-targets	:= clean cleandep cleanout realclean groups.cleanout

ifeq ($(strip $(DEP)),)
$(error No DEP defined in sub-make)
endif
ifeq ($(filter $(no-deps-targets), $(MAKECMDGOALS)),)
-include $(wildcard $(DEP))
endif

.SECONDARY:
