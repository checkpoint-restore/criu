lib-so			+= libcriu
obj-y			+= criu.o

cflags-y		+= -fPIC -Wa,--noexecstack -fno-stack-protector
cflags-so		+= -rdynamic
includes		+= -iquote $(obj)/../arch/$(ARCH)/include -iquote $(obj)/../include -iquote $(obj)/..

.SECONDARY:

#
# We need util-fd.c to be re-compiled with
# own flags, but our build engine can't
# do such tricks yet, so write a rule
# manually for a while.
$(obj)/util-fd.o: $(obj)/../pie/util-fd.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(cflags-y) $(CFLAGS) $(includes) $< -o $@

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
