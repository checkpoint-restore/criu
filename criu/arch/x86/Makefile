builtin-name		:= crtools.built-in.o

ccflags-y		+= -iquote $(obj) -iquote $(SRC_DIR) -iquote $(obj)/include
ccflags-y		+= -iquote $(SRC_DIR)/criu/include -iquote $(SRC_DIR)/include
ccflags-y		+= $(COMPEL_UAPI_INCLUDES)

asflags-y		+= -Wstrict-prototypes
asflags-y		+= -D__ASSEMBLY__ -nostdlib -fomit-frame-pointer
asflags-y		+= -iquote $(obj)/include
ldflags-y		+= -z noexecstack

obj-y			+= cpu.o
obj-y			+= crtools.o
obj-y			+= sigframe.o
ifeq ($(CONFIG_COMPAT),y)
        obj-y		+= sigaction_compat.o
        obj-y		+= call32.o
endif
