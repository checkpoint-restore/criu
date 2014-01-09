-include ../Makefile.inc

ASCIIDOC	:= asciidoc
A2X		:= a2x
XMLTO		:= xmlto

SRC		+= criu.txt
XMLS		:= $(patsubst %.txt,%.xml,$(SRC))
MANS		:= $(patsubst %.txt,%.8,$(SRC))
MAN8DIR		:= $(MANDIR)/man8

all: $(MANS)

%.8: %.txt
	$(E) "  GEN     " $@
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o $(patsubst %.8,%.xml,$@) $<
	$(Q) $(XMLTO) man --skip-validation $(patsubst %.8,%.xml,$@) 2>/dev/null

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f $(XMLS) $(MANS)

install: $(MANS)
	$(E) "  INSTALL " $(MANS)
	$(Q) mkdir -p $(DESTDIR)$(MAN8DIR)
	$(Q) install $(MANS) $(DESTDIR)$(MAN8DIR)

.PHONY: clean install
