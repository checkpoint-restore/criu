obj-y			+= criu.o

cflags-y		+= -shared -fPIC -Wa,--noexecstack -fno-stack-protector
LDFLAGS			+= --export-dynamic
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

$(obj)/built-in.o: $(obj)/util-fd.o

$(obj)/libcriu.so: $(obj)/built-in.o
	$(E) "  GEN     " $@
	$(Q) $(CC) $(CFLAGS) -shared $^ -o $@

_all += $(obj)/built-in.o
cleanup-y += $(obj)/*.so

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
