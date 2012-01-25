-include ../../Makefile.inc

SRCS	+= test-counter.c
SRCS	+= test-rnd-from-file.c
SRCS	+= test-shmem-async.c
SRCS	+= test-shmem-three-async.c
SRCS	+= test-pipe-async.c
SRCS	+= test-vdso.c
SRCS	+= test-sigaction.c
SRCS	+= test-unixsocket.c

SRCS-TH	+= test-pthreads.c
OBJS-TH += $(patsubst %.c,%.o,$(SRCS-TH))
PROGS-TH:= $(patsubst %.c,%,$(SRCS-TH))

OBJS	:= $(patsubst %.c,%.o,$(SRCS))
PROGS	:= $(patsubst %.c,%,$(SRCS))

all: $(PROGS) $(PROGS-TH)

$(PROGS-TH): $(OBJS-TH)
	$(E) "  LINK    " $@
	$(Q) $(CC) $@.o -lpthread -o $@

$(PROGS): $(OBJS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $@.o -o $@

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

clean:
	$(Q) $(RM) -f ./*.o
	$(Q) $(RM) -f ./$(PROGS)
	$(Q) $(RM) -f ./$(PROGS-TH)
	$(Q) $(RM) -f ./f1-file
.PHONY: clean
