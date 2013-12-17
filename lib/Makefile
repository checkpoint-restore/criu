lib-so			+= libcriu
obj-y			+= criu.o
obj-ext-src-y		+= protobuf/rpc.pb-c.o

includes		+= -iquote $(obj)/../arch/$(ARCH)/include -iquote $(obj)/../include -iquote $(obj)/.. -iquote $(obj)/../protobuf
cflags-y		+= $(includes) -fPIC -Wa,--noexecstack -fno-stack-protector
cflags-so		+= -rdynamic
ldflags-so		+= -lprotobuf-c

.SECONDARY:

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
