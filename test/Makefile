TST = $(shell ./zdtm.sh -l)
RM := rm -f --one-file-system

ZDTM_ARGS ?= -C

.FORCE:

all:
	$(MAKE) zdtm
	$(MAKE) zdtm-pre-dump
	$(MAKE) zdtm-snapshot
	$(MAKE) zdtm-iter

.PHONY: all

TESTS = unix-callback mem-snap rpc libcriu mounts/ext security

other: .FORCE
	for t in $(TESTS); do			\
		$(MAKE) -C $$t run || break;	\
	done					\

zdtm: .FORCE 
	$(MAKE) zdtm_ns
	$(MAKE) zdtm_nons

zdtm-pre-dump:
	ZDTM_ARGS="-P -p -i 3 -C" $(MAKE) ns/static/pipe00

zdtm-snapshot:
	ZDTM_ARGS="-s -i 3 -C" $(MAKE) ns/static/pipe00

zdtm-iter:
	ZDTM_ARGS="-i 3 -C" $(MAKE) ns/static/pipe00

.PHONY: zdtm

fault-injection: .FORCE
	$(MAKE) -C fault-injection
.PHONY: fault-injection

zdtm_ns:   $(shell echo "$(TST)" | tr ' ' '\n' | awk '/^ns\// && !/tty|pty/ {print}')
zdtm_nons: $(shell echo "$(TST)" | tr ' ' '\n' | awk '!/^ns\// || /tty|pty/ {print}')

override CFLAGS += -D_GNU_SOURCE
zdtm_ct: zdtm_ct.c

clean:
	$(RM) zdtm_ct
	$(Q) $(RM) -r ./lib/
	$(Q) $(RM) -r ./lib64/
	$(Q) $(RM) -r ./dump/
	$(Q) $(RM) -r ./tmp
	$(Q) $(RM) *.log
	$(Q) $(MAKE) -C zdtm cleandep clean cleanout
	$(Q) $(MAKE) -C libcriu clean
	$(Q) $(MAKE) -C rpc clean

mount_cgroups: .FORCE
	flock zdtm_mount_cgroups ./zdtm_mount_cgroups

$(TST): zdtm_ct mount_cgroups .FORCE
	./zdtm.sh --ct ${ZDTM_ARGS} $(@) &> $(subst /,_,$@).log; \
	{ ret=$$?; fname=$(subst /,_,$@).log; flock Makefile cat $$fname; unlink $$fname; exit $$ret; }
.PHONY: zdtm_ns
