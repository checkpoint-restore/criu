-include ../Makefile.inc

ASCIIDOC	:= asciidoc
A2X		:= a2x
XMLTO		:= xmlto

SRC		+= criu.txt
XMLS		:= $(patsubst %.txt,%.xml,$(SRC))
MANS		:= $(patsubst %.txt,%.8,$(SRC))
MAN8DIR		:= $(MANDIR)/man8

GROFF=groff
PAPER=$(shell paperconf 2>/dev/null || echo letter)
GROFF_OPTS	:= -Tps -t -dpaper=$(PAPER) -P-p$(PAPER) \
		   -man -msafer -rC1 -rD1 -rS11
PSS		:= $(MANS:%.8=%.ps)
PDFS		:= $(MANS:%.8=%.pdf)

all: check $(MANS)
ps: $(PSS)
pdf: $(PDFS)
.PHONY: all ps pdf check

check:
	$(Q) for B in $(ASCIIDOC) $(A2X) $(XMLTO); do	\
		$$B --version > /dev/null || exit 1;	\
	done

%.8: %.txt
	$(E) "  GEN     " $@
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o $(patsubst %.8,%.xml,$@) $<
	$(Q) $(XMLTO) man --skip-validation $(patsubst %.8,%.xml,$@) 2>/dev/null

%.ps: %.8
	$(E) "  GEN     " $@
	$(Q) $(GROFF) $(GROFF_OPTS) $^ > $@

%.pdf: %.ps
	$(E) "  GEN     " $@
	$(Q) ps2pdf $< $@

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f $(XMLS) $(MANS) $(PSS) $(PDFS)

install: $(MANS)
	$(E) "  INSTALL " $(MANS)
	$(Q) mkdir -p $(DESTDIR)$(MAN8DIR)
	$(Q) install $(MANS) $(DESTDIR)$(MAN8DIR)

.PHONY: clean install
