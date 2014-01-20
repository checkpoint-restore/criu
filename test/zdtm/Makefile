SUBDIRS	=	lib live

default:	all
.PHONY: default lib live

lib:
	$(MAKE) -C lib all

live: lib
	$(MAKE) -C live all

all: lib live
	@true
%:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done
