SUBDIRS	=	streaming transition static

default:	all
.PHONY: default

%:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done
