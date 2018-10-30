builtin-name		:= crtools.built-in.o

ccflags-y		+= -iquote $(obj)/include
ccflags-y		+= -iquote criu/include -iquote include
ccflags-y		+= $(COMPEL_UAPI_INCLUDES)

asflags-y		+= -Wstrict-prototypes
asflags-y		+= -D__ASSEMBLY__ -nostdlib -fomit-frame-pointer
asflags-y		+= -iquote $(obj)/include
ldflags-y		+= -r -z noexecstack

obj-y			+= cpu.o
obj-y			+= crtools.o
obj-y			+= kerndat.o
obj-y			+= sigframe.o
ifeq ($(CONFIG_COMPAT),y)
        obj-y		+= sigaction_compat.o
endif
