ifneq ($(USE_ASCIIDOCTOR),)
ASCIIDOC       := asciidoctor
XMLTO          :=
else
ASCIIDOC	:= asciidoc
XMLTO		:= xmlto
endif
PS2PDF		:= ps2pdf

SRC		+= nmk.txt
XMLS		:= $(patsubst %.txt,%.xml,$(SRC))
MANS		:= $(patsubst %.txt,%.8,$(SRC))

GROFF		:= groff
PAPER		:= $(shell paperconf 2>/dev/null || echo letter)
GROFF_OPTS	:= -Tps -t -dpaper=$(PAPER) -P-p$(PAPER) -man -msafer -rC1 -rD1 -rS11
PSS		:= $(MANS:%.8=%.ps)
PDFS		:= $(MANS:%.8=%.pdf)

ps: $(PSS)
pdf: $(PDFS)
all: check $(MANS)

.PHONY: all ps pdf check clean

check:
	$(Q) for B in $(ASCIIDOC) $(XMLTO); do	\
		$$B --version > /dev/null || exit 1;	\
	done

%.8: %.txt
	$(call msg-gen, $@)
ifneq ($(USE_ASCIIDOCTOR),)
	$(Q) $(ASCIIDOC) -b manpage -d manpage -o $@ $<
else
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o $(patsubst %.8,%.xml,$@) $<
	$(Q) $(XMLTO) man --skip-validation $(patsubst %.8,%.xml,$@) 2>/dev/null
endif

%.ps: %.8
	$(call msg-gen, $@)
	$(Q) $(GROFF) $(GROFF_OPTS) $^ > $@

%.pdf: %.ps
	$(call msg-gen, $@)
	$(Q) $(PS2PDF) $< $@

clean:
	$(call msg-clean, "docs")
	$(Q) $(RM) $(XMLS) $(MANS) $(PSS) $(PDFS)
