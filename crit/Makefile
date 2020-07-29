all-y	+= crit

CC	= gcc
CFLAGS  = -g -Wall

decoder:
	$(Q) $(CC) crit/decoder.c -o crit/decoder

crit/crit: crit/crit-$(PYTHON)
	$(Q) cp $^ $@
crit: crit/crit

crit: crit/crit decoder
.PHONY: crit

clean-crit:
	$(Q) $(RM) crit/crit
	$(Q) $(RM) crit/decoder
.PHONY: clean-crit
clean: clean-crit
mrproper: clean