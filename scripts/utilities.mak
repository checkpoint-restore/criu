# try-cc
# Usage: option = $(call try-cc, source-to-build, cc-options)
try-cc = $(shell sh -c						  		\
	'TMP="$(OUTPUT)$(TMPOUT).$$$$";				  		\
	 echo "$(1)" |						  		\
	 $(CC) $(DEFINES) -x c - $(2) $(3) -o "$$TMP" > /dev/null 2>&1 && echo y;	\
	 rm -f "$$TMP"')

# pkg-config-check
# Usage: ifeq ($(call pkg-config-check, library),y)
pkg-config-check = $(shell sh -c 'pkg-config $(1) && echo y')
