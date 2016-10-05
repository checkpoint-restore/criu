__nmk_dir ?= ../scripts/nmk/scripts/
include $(__nmk_dir)include.mk
include $(__nmk_dir)macro.mk

ASCIIDOC	:= asciidoc
A2X		:= a2x
XMLTO		:= xmlto

FOOTER		:= footer.txt
SRC		+= criu.txt
XMLS		:= $(patsubst %.txt,%.xml,$(SRC))
MANS		:= $(patsubst %.txt,%.8,$(SRC))
MAN8DIR		:= $(MANDIR)/man8

GROFF		:=groff
PAPER		:=$(shell paperconf 2>/dev/null || echo letter)
GROFF_OPTS	:= -Tps -t -dpaper=$(PAPER) -P-p$(PAPER) -man -msafer -rC1 -rD1 -rS11
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

ifeq ($(CRIU_VERSION),)
 include ../Makefile.versions
endif
$(FOOTER): ../Makefile.versions
	$(call msg-gen, $@)
	$(Q) echo ":doctype:       manpage"		>  $@
	$(Q) echo ":man source:    criu"		>> $@
	$(Q) echo ":man version:   $(CRIU_VERSION)"	>> $@
	$(Q) echo ":man manual:    CRIU Manual"		>> $@

%.8: %.txt $(FOOTER) custom.xsl
	$(call msg-gen, $@)
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o $(patsubst %.8,%.xml,$@) $<
	$(Q) $(XMLTO) man -m custom.xsl $(patsubst %.8,%.xml,$@) 2>/dev/null

%.ps: %.8
	$(call msg-gen, $@)
	$(Q) $(GROFF) $(GROFF_OPTS) $^ > $@

%.pdf: %.ps
	$(call msg-gen, $@)
	$(Q) ps2pdf $< $@

clean:
	$(call msg-clean, "Documentation")
	$(Q) rm -f $(XMLS) $(MANS) $(PSS) $(PDFS) $(FOOTER)

install: $(MANS)
	$(E) "  INSTALL " $(MANS)
	$(Q) mkdir -p $(DESTDIR)$(MAN8DIR)
	$(Q) install -m 644 $(MANS) $(DESTDIR)$(MAN8DIR)

uninstall:
	$(E) " UNINSTALL" $(MANS)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(MAN8DIR)/,$(MANS))

.PHONY: clean install uninstall
