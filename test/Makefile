RM := rm -f --one-file-system

ZDTM_ARGS ?= -C
export ZDTM_ARGS

.FORCE:

all:
	$(MAKE) zdtm
	$(MAKE) zdtm-pre-dump
	$(MAKE) zdtm-snapshot
	$(MAKE) zdtm-iter
	$(MAKE) zdtm-freezer

.PHONY: all

TESTS = unix-callback mem-snap rpc libcriu mounts/ext security pipes crit socketpairs overlayfs

other: .FORCE
	for t in $(TESTS); do				\
		setsid $(MAKE) -C $$t run || exit 1;	\
	done						\

zdtm_ct: zdtm_ct.c

zdtm: .FORCE
	./zdtm.py run -a --parallel 2

zdtm-pre-dump:
	./zdtm.py run --pre 2:1 -t zdtm/transition/fork -f uns

zdtm-snapshot:
	./zdtm.py run --pre 2:1 --snap -t zdtm/transition/fork -f uns

zdtm-iter:
	./zdtm.py run --iters 3:1 -t zdtm/transition/fork -f uns

zdtm-freezer:
	./zdtm.py run --test zdtm/transition/thread-bomb --pre 3 --freezecg zdtm:t
	./zdtm.py run --test zdtm/transition/thread-bomb --pre 3 --freezecg zdtm:f

.PHONY: zdtm

fault-injection: .FORCE
	$(MAKE) -C fault-injection
.PHONY: fault-injection

override CFLAGS += -D_GNU_SOURCE

clean_root:
	$(Q) ./zdtm.py clean nsroot

clean: clean_root
	$(RM) zdtm_ct zdtm-tst-list
	$(Q) $(RM) *.log
	$(Q) $(RM) -r ./dump/
	$(Q) $(MAKE) -C zdtm cleandep clean cleanout
	$(Q) $(MAKE) -C libcriu clean
	$(Q) $(MAKE) -C rpc clean
	$(Q) $(MAKE) -C crit clean

.PHONY: zdtm_ns
