regression:
	bash ./regression.sh

shared-regression:
	python3 ./shared_regression.py

read-fault-regression:
	python3 ./read_fault_regression.py

runc-redis-regression:
	python3 ./redis_oracle_selftest.py
	python3 ./runc_redis_selftest.py
	python3 ./runc_redis_regression.py

check:
	$(MAKE) PRE_DUMP_MODE=splice regression
	$(MAKE) PRE_DUMP_MODE=read regression
	$(MAKE) shared-regression
	$(MAKE) read-fault-regression

.PHONY: regression shared-regression read-fault-regression runc-redis-regression check
