SUBDIRS	:=	lib static transition

all: $(SUBDIRS)
.PHONY: all $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ all

static: lib
transition: lib

%:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done
