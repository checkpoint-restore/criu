builtin-name		:= crtools.built-in.o

asflags-y		+= -Wstrict-prototypes
asflags-y		+= -nostdlib -fomit-frame-pointer
asflags-y		+= -iquote $(obj)/include
ldflags-y		+= -r -z noexecstack

obj-y			+= cpu.o
obj-y			+= crtools.o
obj-y			+= kerndat.o
obj-y			+= sigframe.o
ifeq ($(CONFIG_COMPAT),y)
        obj-y		+= sigaction_compat.o
endif
