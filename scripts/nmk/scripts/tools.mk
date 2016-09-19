ifndef ____nmk_defined__tools

#
# System tools shorthands
RM		:= rm -f
LD		:= $(CROSS_COMPILE)ld
CC		:= $(CROSS_COMPILE)gcc
CPP		:= $(CC) -E
AS		:= $(CROSS_COMPILE)as
AR		:= $(CROSS_COMPILE)ar
STRIP		:= $(CROSS_COMPILE)strip
OBJCOPY		:= $(CROSS_COMPILE)objcopy
OBJDUMP		:= $(CROSS_COMPILE)objdump
NM		:= $(CROSS_COMPILE)nm
MAKE		:= make
MKDIR		:= mkdir -p
AWK		:= awk
PERL		:= perl
PYTHON		:= python
FIND		:= find
SH		:= $(shell if [ -x "$$BASH" ]; then echo $$BASH;        \
                        else if [ -x /bin/bash ]; then echo /bin/bash;  \
                        else echo sh; fi ; fi)
CSCOPE		:= cscope
ETAGS		:= etags
CTAGS		:= ctags

export RM LD CC CPP AS AR STRIP OBJCOPY OBJDUMP
export NM SH MAKE MKDIR AWK PERL PYTHON SH CSCOPE

#
# Footer.
____nmk_defined__tools = y
endif
