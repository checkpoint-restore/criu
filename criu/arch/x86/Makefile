builtin-name		:= crtools.built-in.o

ccflags-y		+= -iquote $(obj) -iquote $(SRC_DIR) -iquote $(obj)/include
ccflags-y		+= -iquote $(SRC_DIR)/criu/include -iquote $(SRC_DIR)/include
ccflags-y		+= -iquote $(SRC_DIR)/compel/plugins/include
ccflags-y		+= -iquote $(SRC_DIR)/compel/include

asflags-y		+= -Wstrict-prototypes -Wa,--noexecstack
asflags-y		+= -D__ASSEMBLY__ -nostdlib -fomit-frame-pointer
asflags-y		+= -iquote $(obj)/include

obj-y			+= cpu.o
obj-y			+= crtools.o
obj-y			+= sigframe.o
ifeq ($(CONFIG_COMPAT),y)
        obj-y		+= sigaction_compat.o
        obj-y		+= call32.o
endif
