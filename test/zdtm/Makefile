SUBDIRS	=	lib static transition

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
