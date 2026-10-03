regression:
	bash ./regression.sh

shared-regression:
	python3 ./shared_regression.py

check:
	$(MAKE) PRE_DUMP_MODE=splice regression
	$(MAKE) PRE_DUMP_MODE=read regression
	$(MAKE) shared-regression

.PHONY: regression shared-regression check
