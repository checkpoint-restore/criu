# Tests for the build system

run: libbsd
	./uninstall.sh
.PHONY: run

libbsd:
	$(MAKE) -C ../../.. -f test/others/make/libbsd.mk NO_LIBBSD=1 LIBBSD_RESULT=true
	$(MAKE) -C ../../.. -f test/others/make/libbsd.mk NO_LIBBSD= LIBBSD_RESULT=true
	$(MAKE) -C ../../.. -f test/others/make/libbsd.mk NO_LIBBSD= LIBBSD_RESULT=false
.PHONY: libbsd
