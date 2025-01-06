CC	:= gcc
CFLAGS	?= -O2 -g -Wall -Werror

COMPEL		:= ../../../compel/compel-host

all: victim spy

run:
	./spy
.PHONY: run

clean:
	rm -f victim
	rm -f spy
	rm -f parasite.h
	rm -f parasite.po
	rm -f parasite.o

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $^

spy: spy.c parasite.h
	$(CC) $(CFLAGS) $(shell $(COMPEL) includes) -o $@ $< $(shell $(COMPEL) --static libs)

parasite.h: parasite.po
	$(COMPEL) hgen -o $@ -f $<

parasite.po: parasite.o
	ld $(shell $(COMPEL) ldflags) -o $@ $^ $(shell $(COMPEL) plugins)

parasite.o: parasite.c
	$(CC) $(CFLAGS) -c $(shell $(COMPEL) cflags) -o $@ $^
