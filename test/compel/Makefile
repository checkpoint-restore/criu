# Relative path to original objects
define compel_obj_path
        $(addprefix ../../compel/,$(1))
endef

host-ccflags-y		+= -iquote test/compel/arch/$(ARCH)/include
test_objs		:= $(filter-out main.o,$(compel-objs))

hostprogs-y		+= handle_binary
handle_binary-objs	+= $(call compel_obj_path,$(test_objs))
handle_binary-objs	+= main.o
handle_binary-objs	+= handle_binary.o

ifeq ($(ARCH),x86)
    handle_binary-objs	+= handle_binary_32.o
    HOSTCFLAGS_handle_binary.o		+= -DCONFIG_X86_64
    HOSTCFLAGS_handle_binary_32.o	+= -DCONFIG_X86_32
endif
