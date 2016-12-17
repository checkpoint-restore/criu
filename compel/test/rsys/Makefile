CC	:= gcc
CFLAGS	?= -O2 -g -Wall -Werror

COMPEL_IDIR	:= ../../../compel/include/uapi
COMPEL_LIBRARY	:= ../../../compel/libcompel.a

all: victim spy

clean:
	rm -f victim
	rm -f spy

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $^

spy: spy.c
	$(CC) $(CFLAGS) -I$(COMPEL_IDIR) -o $@ $^ $(COMPEL_LIBRARY)
