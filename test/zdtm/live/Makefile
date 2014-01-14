SUBDIRS	=	streaming transition static

default:	all

%:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done
