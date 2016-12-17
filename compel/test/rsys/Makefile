CC	:= gcc
CFLAGS	?= -O2 -g -Wall -Werror

COMPEL		:= ../../../compel/compel-host
COMPEL_LIBRARY	:= ../../../compel/libcompel.a

all: victim spy

clean:
	rm -f victim
	rm -f spy

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $^

spy: spy.c
	$(CC) $(CFLAGS) $(shell $(COMPEL) includes) -o $@ $^ $(COMPEL_LIBRARY)
