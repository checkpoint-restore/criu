lib-so			+= libcriu
obj-y			+= criu.o
obj-ext-src-y		+= pie/util-fd.o

includes		+= -iquote $(obj)/../arch/$(ARCH)/include -iquote $(obj)/../include -iquote $(obj)/..
cflags-y		+= $(includes) -fPIC -Wa,--noexecstack -fno-stack-protector
cflags-so		+= -rdynamic

.SECONDARY:

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
