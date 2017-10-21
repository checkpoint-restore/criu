__nmk_dir=scripts/
export __nmk_dir

include $(__nmk_dir)include.mk

MAKEFLAGS := -r -R --no-print-directory

help:
	@echo '    Targets:'
	@echo '      install dir=<dir>  - Install scripts into directory <dir>'
	@echo '      docs               - Build documentation'
	@echo '      clean              - Clean everything'

test:
	$(Q) $(MAKE) -C tests all

docs:
	$(Q) $(MAKE) -C Documentation all

install:
	@echo 'Copying scripts into $(dir)'
	@cp scripts/build.mk $(dir)
	@cp scripts/include.mk $(dir)
	@cp scripts/macro.mk $(dir)
	@cp scripts/main.mk $(dir)
	@cp scripts/rules.mk $(dir)
	@cp scripts/tools.mk $(dir)
	@cp scripts/utils.mk $(dir)

all: ;

clean:
	$(call msg-clean, "nmk")
	$(Q) $(MAKE) -C Documentation clean
	$(Q) $(MAKE) -C tests clean

.DEFAULT_GOAL ?= all
