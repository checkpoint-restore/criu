local:
	./travis-tests
.PHONY: local

after_success:
	./travis-after_success
.PHONY: after_success

%:
	$(MAKE) -C ../build $@
