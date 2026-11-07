all: fdspy infect rsys shexec stack

fdspy:
	$(Q) $(MAKE) -C fdspy
	$(Q) $(MAKE) -C fdspy run
.PHONY: fdspy

infect:
	$(Q) $(MAKE) -C infect
	$(Q) $(MAKE) -C infect run
.PHONY: infect

rsys:
	$(Q) $(MAKE) -C rsys
	$(Q) $(MAKE) -C rsys run
.PHONY: rsys

shexec:
	$(Q) $(MAKE) -C shexec
	$(Q) $(MAKE) -C shexec run
.PHONY: shexec

stack:
	$(Q) $(MAKE) -C stack
	$(Q) $(MAKE) -C stack run
.PHONY: stack
