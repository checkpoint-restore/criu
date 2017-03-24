builtin-name		:= crtools.built-in.o

ccflags-y		+= -iquote $(obj)/include
ccflags-y		+= -iquote criu/include -iquote include
ccflags-y		+= $(COMPEL_UAPI_INCLUDES)
ldflags-y		+= -r

obj-y			+= cpu.o
obj-y			+= crtools.o
obj-y			+= sigframe.o
