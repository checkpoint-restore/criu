TST = $(shell ./zdtm.sh -l)
EXP = '^ns/(?!.*(tty|pty))'

.FORCE:

all: .FORCE
	$(MAKE) zdtm

zdtm: .FORCE
	$(MAKE) zdtm_ns
	for t in $(shell echo "$(TST)" | tr ' ' '\n' | grep -Pv $(EXP)); do \
		$(MAKE) $$t || break;	\
	done

fault-injection: .FORCE
	$(MAKE) -C fault-injection

zdtm_ns: $(shell echo "$(TST)" | tr ' ' '\n' | grep -P $(EXP))
$(TST):
	./zdtm.sh $(@) &> $(subst /,_,$@).log
