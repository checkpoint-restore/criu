SUBDIRS	=	lib live

default:	all

%:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done
