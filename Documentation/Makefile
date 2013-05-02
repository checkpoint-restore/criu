-include ../Makefile.inc

ASCIIDOC	:= asciidoc
A2X		:= a2x
XMLTO		:= xmlto

SRC		+= criu.txt
MANS		:= $(patsubst %.txt,%.8,$(SRC))

all: $(MANS)

%.8: %.txt
	$(E) "  GEN     " $@
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o $(patsubst %.8,%.xml,$@) $<
	$(Q) $(XMLTO) man --skip-validation $(patsubst %.8,%.xml,$@) 2>/dev/null

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f ./*.xml
	$(Q) rm -f ./*.1

.PHONY: clean
