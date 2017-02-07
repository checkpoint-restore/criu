local:
	./travis-tests
.PHONY: local

after_success:
	./travis-after_success
.PHONY: after_success

alpine:
	$(MAKE) -C ../build alpine
	docker run --rm -it --privileged -v /lib/modules:/lib/modules criu-alpine ./test/zdtm.py run -t zdtm/static/env00

%:
	$(MAKE) -C ../build $@
