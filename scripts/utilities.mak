# try-cc
# Usage: option = $(call try-cc, source-to-build, cc-options)
try-cc = $(shell sh -c						  \
	'TMP="$(OUTPUT)$(TMPOUT).$$$$";				  \
	 echo "$(1)" |						  \
	 $(CC) -x c - $(2) -o "$$TMP" > /dev/null 2>&1 && echo y; \
	 rm -f "$$TMP"')

# try-build
# Usage: option = $(call try-build, source-to-build, cc-options, link-options)
try-build = $(shell sh -c							\
	'TMP="$(OUTPUT)$(TMPOUT).$$$$";						\
	echo "$(1)" |								\
	$(CC) -x c - $(2) $(3) -o "$$TMP" > /dev/null 2>&1 && echo y;		\
	rm -f "$$TMP"')
