#
# Common definitions
#

ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif
export E Q

FIND		:= find
CSCOPE		:= cscope
TAGS		:= ctags
RM		:= rm
LD		:= ld
HEXDUMP		:= hexdump
CC		:= gcc
ECHO		:= echo
NM		:= nm
AWK		:= awk
SH		:= sh
MAKE		:= make

# Additional ARCH settings for x86
ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ \
                  -e s/arm.*/arm/ -e s/sa110/arm/ \
                  -e s/s390x/s390/ -e s/parisc64/parisc/ \
                  -e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
                  -e s/sh[234].*/sh/ )

uname_M      := $(shell uname -m | sed -e s/i.86/i386/)
ifeq ($(uname_M),i386)
	ARCH         := x86
	DEFINES      += -DCONFIG_X86_32
endif
ifeq ($(uname_M),x86_64)
	ARCH         := x86
	DEFINES      += -DCONFIG_X86_64
endif

no-deps-targets := tags cscope clean cleanout cleandep realclean

CFLAGS		+= -I./include -fno-strict-aliasing

LIBS		+= -lrt -lpthread -lprotobuf-c

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
	CFLAGS	+= -O0 -ggdb3
else
	CFLAGS	+= -O2
endif

WARNINGS	+= -Wall
CFLAGS		+= $(WARNINGS) $(DEFINES)

export CC ECHO MAKE CFLAGS LIBS ARCH DEFINES
