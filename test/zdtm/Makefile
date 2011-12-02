SUBDIRS	=	lib live

default:	all

.PHONY:	default

%:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d $@; done
