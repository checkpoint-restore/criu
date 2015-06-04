CFLAGS += -iquote pie/piegen

obj-y += main.o
ifneq ($(filter i386 ia32 x86_64, $(ARCH)),)
obj-y += elf-x86-32.o
obj-y += elf-x86-64.o
endif
ifeq ($(SRCARCH),ppc64)
obj-y += elf-ppc64.o
endif

cleanup-y += $(obj)/piegen
cleanup-y += $(obj)/*.o

ifneq ($(MAKECMDGOALS),clean)
incdeps := y
endif
