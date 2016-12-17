CC	:= gcc
CFLAGS	?= -O2 -g -Wall -Werror

COMPEL		:= ../../../compel/compel-host
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

spy: spy.c parasite.h
	$(CC) $(CFLAGS) $(shell $(COMPEL) includes) -o $@ $< $(COMPEL_LIBRARY)

parasite.h: parasite.po
	$(COMPEL) hgen -f $^ -l 4		\
		-p parasite			\
		-o $@

parasite.po: parasite.o
	ld $(shell $(COMPEL) ldflags) -o $@ $^ $(shell $(COMPEL) plugins)

parasite.o: parasite.c
	$(CC) $(CFLAGS) -c $(shell $(COMPEL) cflags) -o $@ $^
