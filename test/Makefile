RM := rm -f --one-file-system

ZDTM_ARGS ?= -C

.FORCE:

all:
	$(MAKE) zdtm
	$(MAKE) zdtm-pre-dump
	$(MAKE) zdtm-snapshot
	$(MAKE) zdtm-iter

.PHONY: all

TESTS = unix-callback mem-snap rpc libcriu mounts/ext security pipes crit

other: .FORCE
	for t in $(TESTS); do			\
		$(MAKE) -C $$t run || break;	\
	done					\

zdtm-tst-list: zdtm.sh
	./zdtm.sh -l > zdtm-tst-list

zdtm: zdtm-tst-list .FORCE 
	$(MAKE) -f Makefile.zdtm zdtm_nons
	$(MAKE) -f Makefile.zdtm zdtm_ns
	$(MAKE) clean_root
	$(MAKE) -f Makefile.zdtm zdtm_ns_user

zdtm-pre-dump: zdtm-tst-list
	ZDTM_ARGS="-P -p -i 3 -C" $(MAKE) -f Makefile.zdtm ns/static/pipe00

zdtm-snapshot: zdtm-tst-list
	ZDTM_ARGS="-s -i 3 -C" $(MAKE) -f Makefile.zdtm ns/static/pipe00

zdtm-iter: zdtm-tst-list
	ZDTM_ARGS="-i 3 -C" $(MAKE) -f Makefile.zdtm ns/static/pipe00

.PHONY: zdtm

fault-injection: .FORCE
	$(MAKE) -C fault-injection
.PHONY: fault-injection

override CFLAGS += -D_GNU_SOURCE

clean_root:
	$(Q) $(RM) -r ./lib/
	$(Q) $(RM) -r ./lib64/
	$(Q) $(RM) -r ./tmp
	$(Q) $(RM) -r ./etc
	$(Q) $(RM) -r ./dev
	$(Q) $(RM) -r ./bin

clean: clean_root
	$(RM) zdtm_ct zdtm-tst-list
	$(Q) $(RM) *.log
	$(Q) $(RM) -r ./dump/
	$(Q) $(MAKE) -C zdtm cleandep clean cleanout
	$(Q) $(MAKE) -C libcriu clean
	$(Q) $(MAKE) -C rpc clean
	$(Q) $(MAKE) -C crit clean

.PHONY: zdtm_ns
