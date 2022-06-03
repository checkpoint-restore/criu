RM := rm -f --one-file-system

ZDTM_ARGS ?= -C
export ZDTM_ARGS

all:
	$(MAKE) zdtm
	$(MAKE) zdtm-config
	$(MAKE) zdtm-pre-dump
	$(MAKE) zdtm-snapshot
	$(MAKE) zdtm-iter
	$(MAKE) zdtm-freezer
.PHONY: all

TESTS = unix-callback mem-snap rpc libcriu mounts/ext security pipes crit socketpairs overlayfs mnt-ext-dev shell-job skip-file-rwx-check

other:
	for t in $(TESTS); do				\
		setsid $(MAKE) -C others/$$t run || exit 1;	\
	done
.PHONY: other

zdtm:
	./zdtm.py run -a --parallel 2
.PHONY: zdtm

zdtm-config:
	./zdtm.py run -a --parallel 2 --criu-config
.PHONY: zdtm-config

zdtm-pre-dump:
	./zdtm.py run --pre 2:1 -t zdtm/transition/fork -f uns
.PHONY: zdtm-pre-dump

zdtm-snapshot:
	./zdtm.py run --pre 2:1 --snap -t zdtm/transition/fork -f uns
.PHONY: zdtm-snapshot

zdtm-iter:
	./zdtm.py run --iters 3:1 -t zdtm/transition/fork -f uns
.PHONY: zdtm-iter

zdtm-freezer:
	./zdtm.py run --test zdtm/transition/thread-bomb --pre 3 --freezecg zdtm:t
	./zdtm.py run --test zdtm/transition/thread-bomb --pre 3 --freezecg zdtm:f
.PHONY: zdtm-freezer

fault-injection:
	$(MAKE) -C fault-injection
.PHONY: fault-injection

override CFLAGS += -D_GNU_SOURCE

clean_root:
	$(Q) ./zdtm.py clean nsroot
.PHONY: clean_root

clean: clean_root
	$(RM) zdtm_ct zdtm-tst-list umount2
	$(Q) $(RM) *.log
	$(Q) $(RM) -r ./dump/
	$(Q) $(MAKE) -C zdtm cleandep clean cleanout
	$(Q) $(MAKE) -C libcriu clean
	$(Q) $(MAKE) -C rpc clean
	$(Q) $(MAKE) -C crit clean
.PHONY: clean
