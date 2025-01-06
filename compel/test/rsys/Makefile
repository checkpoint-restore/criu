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

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $^

spy: spy.c
	$(CC) $(CFLAGS) $(shell $(COMPEL) includes) -o $@ $^ $(shell $(COMPEL) --static libs)
