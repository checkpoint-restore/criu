SUBDIRS	=	lib static transition

ifeq ($(COMPAT_TEST),y)
ifeq ($(ARCH),x86)
        export USERCFLAGS += -m32
        export CFLAGS += -m32
        export LDFLAGS += -m32
endif
endif

default:	all
.PHONY: default lib static transition

lib:
	$(MAKE) -C lib all

static: lib
	$(MAKE) -C static all

transition: lib
	$(MAKE) -C transition all

all: lib static transition
	@true
%:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done
