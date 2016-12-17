CC	:= gcc
CFLAGS	?= -O2 -g -Wall -Werror
ARCH	?= x86

COMPEL		:= ../../../compel/compel-host
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
	$(CC) $(CFLAGS) -o $@ $^

spy: spy.c | parasite.h
	$(CC) $(CFLAGS) $(shell $(COMPEL) includes) -o $@ $^ $(COMPEL_LIBRARY)

parasite.h: parasite.po
	$(COMPEL) hgen -f $^ -l 4		\
		-p parasite			\
		-o $@

parasite.po: parasite.o $(COMPEL_PLUGINS)/std.built-in.o
	ld -r -T $(COMPEL_PACK_LDS) -o $@ $^

parasite.o: parasite.c
	$(CC) $(CFLAGS) -c $(shell $(COMPEL) cflags) -o $@ $^
