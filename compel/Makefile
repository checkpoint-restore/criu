include $(SRC_DIR)/Makefile.versions

ccflags-y	+= -iquote criu/include
ccflags-y	+= -iquote compel/include
ccflags-y	+= -DCOMPEL_VERSION=\"$(COMPEL_SO_VERSION_MAJOR).$(COMPEL_SO_VERSION_MINOR)\"

host-ccflags-y	+= $(filter-out -pg $(CFLAGS-GCOV),$(ccflags-y))
HOSTCFLAGS	+= $(filter-out -pg $(CFLAGS-GCOV),$(WARNINGS) $(DEFINES))
HOSTLDFLAGS	+= $(filter-out -pg $(CFLAGS-GCOV),$(LDFLAGS))

hostprogs-y	+= compel
compel-objs	+= src/main.o

ifneq ($(filter ia32 x86, $(ARCH)),)
compel-objs	+= src/elf-x86-32.o
compel-objs	+= src/elf-x86-64.o
endif
ifeq ($(SRCARCH),ppc64)
compel-objs	+= src/elf-ppc64.o
endif
