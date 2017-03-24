obj-y			+= criu.o
obj-y			+= ./images/rpc.pb-c.o

ccflags-y		+= -iquote criu/$(ARCH_DIR)/include
ccflags-y		+= -iquote criu/include
ccflags-y		+= -iquote images
ccflags-y		+= -fPIC -fno-stack-protector
ldflags-y		+= -r -z noexecstack
