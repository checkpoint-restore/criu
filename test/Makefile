TST = $(shell ./zdtm.sh -l)
RM := rm -f --one-file-system

ZDTM_ARGS ?= -C

.FORCE:

all: .FORCE
	$(MAKE) zdtm
.PHONY: all

TESTS = unix-callback mem-snap rpc libcriu mounts/ext security

other: .FORCE
	for t in $(TESTS); do			\
		$(MAKE) -C $$t run || break;	\
	done					\

zdtm: .FORCE 
	$(MAKE) zdtm_ns
	$(MAKE) zdtm_nons
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
	./zdtm.sh --ct ${ZDTM_ARGS} $(@) &> $(subst /,_,$@).log || \
	{ flock Makefile cat $(subst /,_,$@).log; exit 1; }
.PHONY: zdtm_ns
