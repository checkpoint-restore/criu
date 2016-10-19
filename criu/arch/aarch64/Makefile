builtin-name		:= crtools.built-in.o

ccflags-y		+= -iquote $(obj) -iquote $(SRC_DIR)
ccflags-y		+= -iquote $(obj)/include -iquote $(SRC_DIR)/criu/include
ccflags-y		+= -iquote $(SRC_DIR)/include
ccflags-y		+= -iquote $(SRC_DIR)/compel/plugins/include
ccflags-y		+= -iquote $(SRC_DIR)/compel/include
asflags-y		+= -D__ASSEMBLY__

obj-y			+= cpu.o
obj-y			+= crtools.o
obj-y			+= sigframe.o
obj-y			+= bitops.o
obj-y			+= infect.o
