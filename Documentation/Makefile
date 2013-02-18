-include ../Makefile.inc

ASCIIDOC	:= asciidoc
A2X		:= a2x
XMLTO		:= xmlto

SRC		+= crtools.txt
SRC		+= Makefile.build.txt
MANS		:= $(patsubst %.txt,%.1,$(SRC))

all: $(MANS)

%.1: %.txt
	$(E) "  GEN     " $@
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o $(patsubst %.1,%.xml,$@) $<
	$(Q) $(XMLTO) man --skip-validation $(patsubst %.1,%.xml,$@) 2>/dev/null

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f ./*.xml
	$(Q) rm -f ./*.1
