ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif

export E Q

ASCIIDOC	:= asciidoc
A2X		:= a2x
XMLTO		:= xmlto

SRC		+= bers.txt
XMLS		:= $(patsubst %.txt,%.xml,$(SRC))
MANS		:= $(patsubst %.txt,%.8,$(SRC))

%.8: %.txt
	$(E) "  GEN     " $@
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o $(patsubst %.8,%.xml,$@) $<
	$(Q) $(XMLTO) man --skip-validation $(patsubst %.8,%.xml,$@) 2>/dev/null

docs: $(MANS)
	@true

CFLAGS := -O0 -ggdb3
LIBS := -lpthread

%.o: %.c
	$(E) "  CC      " $@
	$(Q) $(CC) -c -o $@ $(CFLAGS) $^

bers: bers.o
	$(E) "  LINK    " $@
	$(Q) $(CC) -o $@ $(CFLAGS) $(LIBS) $^

all: bers
	@true

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f $(XMLS) $(MANS)
	$(Q) rm -f bers.o
	$(Q) rm -f bers

.PHONY: all docs clean
