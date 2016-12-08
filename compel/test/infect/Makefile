ifeq ($(ARCH),)
        ARCH := x86
endif

# FIXME -- generate common symlink in compel/uapi
COMMON_IDIR	:= ../../../include
COMPEL		:= ../../../compel/compel-host
COMPEL_IDIR	:= ../../../compel/include/uapi
COMPEL_PACK_LDS	:= ../../../compel/arch/$(ARCH)/scripts/compel-pack.lds.S
COMPEL_PLUGINS	:= ../../../compel/plugins
COMPEL_LIBRARY	:= ../../../compel/libcompel.a

all: victim spy

clean:
	rm -f victim
	rm -f spy
	rm -f parasite.h
	rm -f parasite.po
	rm -f parasite.o

victim: victim.c
	gcc -o $@ $^

spy: spy.c parasite.h $(COMPEL_LIBRARY)
	gcc -Werror -I$(COMPEL_IDIR) -I$(COMMON_IDIR) -o $@ $^

parasite.h: parasite.po
	$(COMPEL) hgen -f $^ -l 4		\
		-p parasite			\
		-u $(COMPEL_IDIR)		\
		-o $@

parasite.po: parasite.o $(COMPEL_PLUGINS)/std.built-in.o
	ld -r -T $(COMPEL_PACK_LDS) -o $@ $^

parasite.o: parasite.c
	gcc -c $(shell $(COMPEL) --arch=$(ARCH) cflags) -I$(COMPEL_IDIR) -o $@ $^
