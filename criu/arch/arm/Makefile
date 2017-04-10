builtin-name		:= crtools.built-in.o

ccflags-y		+= -iquote $(obj)/include
ccflags-y		+= -iquote criu/include -iquote include
ccflags-y		+= $(COMPEL_UAPI_INCLUDES)

asflags-y		+= -D__ASSEMBLY__
ldflags-y		+= -r -z noexecstack

obj-y			+= cpu.o
obj-y			+= crtools.o
obj-y			+= sigframe.o
obj-y			+= bitops.o
