obj-y			+= criu.o
obj-y			+= $(SRC_DIR)/images/rpc.pb-c.o

ccflags-y		+= -iquote $(SRC_DIR)/criu/$(ARCH_DIR)/include
ccflags-y		+= -iquote $(SRC_DIR)/criu/include -iquote $(obj)/..
ccflags-y		+= -iquote $(SRC_DIR)/images
ccflags-y		+= -fPIC -Wa,--noexecstack -fno-stack-protector
