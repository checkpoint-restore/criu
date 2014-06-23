TST = $(shell ./zdtm.sh -l)
EXP = '^ns/(?!.*(tty|pty))'

ZDTM_ARGS ?= -C

.FORCE:

all: .FORCE
	$(MAKE) zdtm
.PHONY: all

TESTS = unix-callback mem-snap rpc libcriu

other: .FORCE
	for t in $(TESTS); do			\
		$(MAKE) -C $$t run || break;	\
	done					\

zdtm: .FORCE
	$(MAKE) zdtm_ns
	for t in $(shell echo "$(TST)" | tr ' ' '\n' | grep -Pv $(EXP)); do \
		$(MAKE) $$t || break;	\
	done
.PHONY: zdtm

fault-injection: .FORCE
	$(MAKE) -C fault-injection
.PHONY: fault-injection

zdtm_ns: $(shell echo "$(TST)" | tr ' ' '\n' | grep -P $(EXP))
$(TST):
	./zdtm.sh ${ZDTM_ARGS} $(@) &> $(subst /,_,$@).log || \
	{ flock Makefile cat $(subst /,_,$@).log; exit 1; }
.PHONY: zdtm_ns
