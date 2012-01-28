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

MAN		:= crtools.txt

all: man

man: $(MAN)
	$(E) "  GEN     " $@
	$(Q) $(ASCIIDOC) -b docbook -d manpage -o crtools.xml crtools.txt
	$(Q) $(XMLTO) man --skip-validation crtools.xml 2>/dev/null

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f ./*.xml
	$(Q) rm -f ./*.1
