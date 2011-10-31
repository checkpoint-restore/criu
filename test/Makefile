OBJS	+= testee.o
OBJS	+= testee-static.o
OBJS	+= testee-static-syssleep.o
OBJS	+= testee-threads.o
OBJS	+= testee-unlinked.o
OBJS	+= asmem.o

PROGS	:= $(patsubst %.o,%,$(OBJS))

all: $(PROGS)

asmem: asmem.c
	$(E) "  CC      " $(patsubst %.c,%.o,$<)
	$(Q) $(CC) -c $(CFLAGS) $< -o $(patsubst %.c,%.o,$<)
	$(E) "  LINK    " $@
	$(Q) $(CC) -o $@ $(patsubst %.c,%.o,$<)

testee: testee.c
	$(E) "  CC      " $(patsubst %.c,%.o,$<)
	$(Q) $(CC) -c $(CFLAGS) $< -o $(patsubst %.c,%.o,$<)
	$(E) "  LINK    " $@
	$(Q) $(CC) -o $@ $(patsubst %.c,%.o,$<)

testee-static-syssleep: testee-static-syssleep.c
	$(E) "  CC      " $(patsubst %.c,%.o,$<)
	$(Q) $(CC) -c $(CFLAGS) $< -o $(patsubst %.c,%.o,$<)
	$(E) "  LINK    " $@
	$(Q) $(CC) -static -o $@ $(patsubst %.c,%.o,$<)

testee-static: testee-static.c
	$(E) "  CC      " $(patsubst %.c,%.o,$<)
	$(Q) $(CC) -c $(CFLAGS) $< -o $(patsubst %.c,%.o,$<)
	$(E) "  LINK    " $@
	$(Q) $(CC) -static -o $@ $(patsubst %.c,%.o,$<)

testee-threads: testee-threads.c
	$(E) "  CC      " $(patsubst %.c,%.o,$<)
	$(Q) $(CC) -c $(CFLAGS) $< -o $(patsubst %.c,%.o,$<)
	$(E) "  LINK    " $@
	$(Q) $(CC) -lpthread -o $@ $(patsubst %.c,%.o,$<)

testee-unlinked: testee-unlinked.c
	$(E) "  CC      " $(patsubst %.c,%.o,$<)
	$(Q) $(CC) -c $(CFLAGS) $< -o $(patsubst %.c,%.o,$<)
	$(E) "  LINK    " $@
	$(Q) $(CC) -o $@ $(patsubst %.c,%.o,$<)

clean:
	$(Q) $(RM) -f ./*.o
	$(Q) $(RM) -f ./$(PROGS)
.PHONY: clean
