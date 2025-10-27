ifndef ____nmk_defined__tools

#
# System tools shorthands
RM		:= rm -f
HOSTLD		?= ld
ifeq ($(origin LD), default)
LD		:= $(CROSS_COMPILE)$(HOSTLD)
endif
HOSTCC		?= gcc
ifeq ($(origin CC), default)
CC		:= $(CROSS_COMPILE)$(HOSTCC)
endif
CPP		:= $(CC) -E
AS		:= $(CROSS_COMPILE)as
AR		:= $(CROSS_COMPILE)ar
STRIP		:= $(CROSS_COMPILE)strip
OBJCOPY		:= $(CROSS_COMPILE)objcopy
OBJDUMP		:= $(CROSS_COMPILE)objdump
PKG_CONFIG	?= pkg-config
NM		:= $(CROSS_COMPILE)nm
MAKE		:= make
MKDIR		:= mkdir -p
AWK		:= awk
PERL		:= perl
FULL_PYTHON	:= $(shell command -v python3 2>/dev/null)
PYTHON		?= $(shell basename $(FULL_PYTHON))
FIND		:= find
SH		:= $(shell if [ -x "$$BASH" ]; then echo $$BASH;        \
                        else if [ -x /bin/bash ]; then echo /bin/bash;  \
                        else echo sh; fi ; fi)
CSCOPE		:= cscope
ETAGS		:= etags
CTAGS		:= ctags

export RM HOSTLD LD HOSTCC CC CPP AS AR STRIP OBJCOPY OBJDUMP
export NM SH MAKE MKDIR AWK PERL PYTHON SH CSCOPE

export USE_ASCIIDOCTOR ?= $(shell command -v asciidoctor 2>/dev/null)

#
# Footer.
____nmk_defined__tools = y
endif
