obj-y			+= criu.o
obj-y			+= $(SRC_DIR)/images/rpc.pb-c.o

ccflags-y		+= -iquote $(SRC_DIR)/crtools/$(ARCH_DIR)/include
ccflags-y		+= -iquote $(SRC_DIR)/crtools/include -iquote $(obj)/..
ccflags-y		+= -iquote $(SRC_DIR)/images
ccflags-y		+= -fPIC -Wa,--noexecstack -fno-stack-protector

#
# Remove once criu moved into proper place.
ccflags-y		+= -iquote $(SRC_DIR)/$(ARCH_DIR)/include
ccflags-y		+= -iquote $(SRC_DIR)/include -iquote $(obj)/..
ccflags-y		+= -iquote $(SRC_DIR)/images
