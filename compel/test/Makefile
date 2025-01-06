all: fdspy infect rsys stack

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

stack:
	$(Q) $(MAKE) -C stack
	$(Q) $(MAKE) -C stack run
.PHONY: stack
