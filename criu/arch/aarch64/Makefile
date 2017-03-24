builtin-name		:= crtools.built-in.o

ccflags-y		+= -iquote $(obj)/include -iquote criu/include
ccflags-y		+= -iquote include
ccflags-y		+= $(COMPEL_UAPI_INCLUDES)
asflags-y		+= -D__ASSEMBLY__
ldflags-y		+= -r

obj-y			+= cpu.o
obj-y			+= crtools.o
obj-y			+= sigframe.o
obj-y			+= bitops.o
