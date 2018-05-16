
all-y	+= crit

crit/crit: crit/crit-$(PYTHON)
	$(Q) cp $^ $@
crit: crit/crit
.PHONY: crit

clean-crit:
	$(Q) $(RM) crit/crit
.PHONY: clean-crit
clean: clean-crit
mrproper: clean
