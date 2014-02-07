lib-so			+= $(CRIU-SO)
obj-y			+= criu.o
obj-ext-src-y		+= protobuf/rpc.pb-c.o

includes		+= -iquote $(obj)/../$(ARCH_DIR)/include -iquote $(obj)/../include -iquote $(obj)/.. -iquote $(obj)/../protobuf
cflags-y		+= $(includes) -fPIC -Wa,--noexecstack -fno-stack-protector
cflags-so		+= $(CFLAGS) -rdynamic -Wl,-soname,$(lib-so).so.$(VERSION_SO_MAJOR)
ldflags-so		+= -lprotobuf-c

.SECONDARY:

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
