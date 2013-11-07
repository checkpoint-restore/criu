lib-so			+= libcriu
obj-y			+= criu.o

includes		+= -iquote $(obj)/../arch/$(ARCH)/include -iquote $(obj)/../include -iquote $(obj)/..
cflags-y		+= $(includes) -fPIC -Wa,--noexecstack -fno-stack-protector
cflags-so		+= -rdynamic

.SECONDARY:

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
