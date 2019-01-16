__nmk_dir ?= ../scripts/nmk/scripts/
include $(__nmk_dir)include.mk
include $(__nmk_dir)macro.mk

ifneq ($(USE_ASCIIDOCTOR),)
ASCIIDOC	:= asciidoctor
XMLTO		:=
else
ASCIIDOC	:= asciidoc
XMLTO		:= xmlto
endif

FOOTER		:= footer.txt
SRC1		+= crit.txt
SRC8		+= criu.txt
SRC		:= $(SRC1) $(SRC8)
XMLS		:= $(patsubst %.txt,%.xml,$(SRC))
MAN1S		:= $(patsubst %.txt,%.1,$(SRC1))
MAN8S		:= $(patsubst %.txt,%.8,$(SRC8))
MANS		:= $(MAN1S) $(MAN8S)
MAN1DIR		:= $(MANDIR)/man1
MAN8DIR		:= $(MANDIR)/man8

GROFF		:=groff
PAPER		:=$(shell paperconf 2>/dev/null || echo letter)
GROFF_OPTS	:= -Tps -t -dpaper=$(PAPER) -P-p$(PAPER) -man -msafer -rC1 -rD1 -rS11
PSS		:= $(patsubst %,%.ps,$(basename $(MANS)))
PDFS		:= $(patsubst %,%.pdf,$(basename $(MANS)))

all: check $(MANS)
ps: $(PSS)
pdf: $(PDFS)
.PHONY: all ps pdf check

check:
	$(Q) for B in $(ASCIIDOC) $(XMLTO); do	\
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

%.1: %.txt $(FOOTER) custom.xsl
	$(call msg-gen, $@)
ifneq ($(USE_ASCIIDOCTOR),)
	$(Q) $(ASCIIDOC) -b manpage -d manpage -o $@ $<
else
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o $(patsubst %.1,%.xml,$@) $<
	$(Q) $(XMLTO) man -m custom.xsl $(patsubst %.1,%.xml,$@) 2>/dev/null
endif

%.8: %.txt $(FOOTER) custom.xsl
	$(call msg-gen, $@)
ifneq ($(USE_ASCIIDOCTOR),)
	$(Q) $(ASCIIDOC) -b manpage -d manpage -o $@ $<
else
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o $(patsubst %.8,%.xml,$@) $<
	$(Q) $(XMLTO) man -m custom.xsl $(patsubst %.8,%.xml,$@) 2>/dev/null
endif

%.ps: %.1
	$(call msg-gen, $@)
	$(Q) $(GROFF) $(GROFF_OPTS) $^ > $@

%.ps: %.8
	$(call msg-gen, $@)
	$(Q) $(GROFF) $(GROFF_OPTS) $^ > $@

%.pdf: %.ps
	$(call msg-gen, $@)
	$(Q) ps2pdf $< $@

clean:
	$(call msg-clean, "Documentation")
	$(Q) rm -f $(XMLS) $(MANS) $(PSS) $(PDFS) $(FOOTER)

install: check $(MANS)
	$(E) "  INSTALL " $(MAN8S)
	$(Q) mkdir -p $(DESTDIR)$(MAN8DIR)
	$(Q) install -m 644 $(MAN8S) $(DESTDIR)$(MAN8DIR)
	$(E) "  INSTALL " $(MAN1S)
	$(Q) mkdir -p $(DESTDIR)$(MAN1DIR)
	$(Q) install -m 644 $(MAN1S) $(DESTDIR)$(MAN1DIR)

uninstall:
	$(E) " UNINSTALL" $(MAN1S)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(MAN1DIR)/,$(MAN1S))
	$(E) " UNINSTALL" $(MAN8S)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(MAN8DIR)/,$(MAN8S))

.PHONY: clean install uninstall
