.SUFFIXES:
MAKEFLAGS	+= -r

SUBARCH ?= $(shell uname -m)
ARCH	?= $(shell echo $(SUBARCH) | sed	\
                -e s/i.86/x86/			\
                -e s/x86_64/x86/		\
                -e s/sun4u/sparc64/		\
                -e s/arm.*/arm/			\
                -e s/sa110/arm/			\
                -e s/s390x/s390/		\
                -e s/parisc64/parisc/		\
                -e s/ppc64.*/ppc64/		\
                -e s/mips.*/mips/		\
                -e s/sh[234].*/sh/		\
                -e s/aarch64.*/arm64/)

ifeq ($(ARCH),arm64)
        ARCH	:= aarch64
endif

ifeq ($(ARCH),arm)
        ARMV := $(shell echo $(SUBARCH) | sed -nr 's/armv([[:digit:]]).*/\1/p; t; i7')

        ifeq ($(ARMV),6)
                ARCHCFLAGS += -march=armv6
        else ifeq ($(ARMV),7)
                ARCHCFLAGS += -march=armv7-a+fp
        else ifeq ($(ARMV),8)
                # To build aarch32 on armv8 (see criu Makefile)
                ARCHCFLAGS += -march=armv7-a
                ARMV := 7
        endif
endif

HOSTCC	?= gcc
ifeq ($(origin CC), default)
        CC := $(CROSS_COMPILE)$(HOSTCC)
endif
PKG_CONFIG ?= pkg-config
CFLAGS	+= -g -O2 -Wall -Werror -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
CFLAGS	+= -Wdeclaration-after-statement -Wstrict-prototypes
CFLAGS	+= $(USERCFLAGS) $(ARCHCFLAGS)
CFLAGS	+= -D_GNU_SOURCE -D_LARGEFILE64_SOURCE
CPPFLAGS += -iquote $(LIBDIR)/arch/$(ARCH)/include

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif

RM := rm -f --one-file-system

ifeq ($(COMPAT_TEST),y)
        # Firstly look for 32-bit libs and then in standard path.
        PKG_CONFIG_PATH := $(shell $(PKG_CONFIG) --variable pc_path pkg-config)
        PKG_CONFIG_PATH := /usr/lib32/pkgconfig:$(PKG_CONFIG_PATH)
ifeq ($(ARCH),x86)
        export CFLAGS += -m32
        export LDFLAGS += -m32
        PKG_CONFIG_PATH := /usr/lib/i386-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
endif
        export PKG_CONFIG_PATH
endif

ifeq ($(SHSTK_ENABLE),1)
        CFLAGS  += -mshstk
        LDFLAGS += -Wl,-z,shstk
endif

define pkg-libs
        $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" $(PKG_CONFIG) --libs $(1))
endef

define pkg-cflags
        $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" $(PKG_CONFIG) --cflags $(1))
endef

%.d: %.c
	$(E) " DEP      " $@
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -MM -MP $< -o $@

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
