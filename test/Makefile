SRCS	+= test-counter.c

OBJS	:= $(patsubst %.c,%.o,$(SRCS))
PROGS	:= $(patsubst %.c,%,$(SRCS))

all: $(PROGS)

$(PROGS): $(OBJS)
	$(E) "  LINK    " $@
	$(Q) $(CC) $< -o $@

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

clean:
	$(Q) $(RM) -f ./*.o
	$(Q) $(RM) -f ./$(PROGS)
.PHONY: clean
