SRCS	+= test-counter.c
SRCS	+= test-rnd-from-file.c
SRCS	+= test-shmem-async.c

OBJS	:= $(patsubst %.c,%.o,$(SRCS))
PROGS	:= $(patsubst %.c,%,$(SRCS))

all: $(PROGS)

$(PROGS): $(OBJS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $@.o -o $@

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

clean:
	$(Q) $(RM) -f ./*.o
	$(Q) $(RM) -f ./$(PROGS)
.PHONY: clean
