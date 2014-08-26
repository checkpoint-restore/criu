TST = $(shell ./zdtm.sh -l)

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
	rm -rf zdtm_ct
	$(MAKE) -C zdtm $@

$(TST): zdtm_ct
	./zdtm.sh --ct ${ZDTM_ARGS} $(@) &> $(subst /,_,$@).log || \
	{ flock Makefile cat $(subst /,_,$@).log; exit 1; }
.PHONY: zdtm_ns
