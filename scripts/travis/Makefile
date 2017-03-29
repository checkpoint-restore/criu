local:
	./travis-tests
.PHONY: local

after_success:
	./travis-after_success
.PHONY: after_success

target-suffix =
ifdef CLANG
	target-suffix = -clang
endif

alpine:
	$(MAKE) -C ../build $@$(target-suffix)
	docker run --rm -it --privileged -v /lib/modules:/lib/modules criu-alpine ./test/zdtm.py run -t zdtm/static/env00

asan:
	echo 'DOCKER_OPTS="--storage-driver=devicemapper"' > /etc/default/docker
	restart docker
	$(MAKE) -C ../build fedora-asan
	docker run --rm -it --privileged -v /lib/modules:/lib/modules criu-fedora-asan ./scripts/travis/asan.sh

%:
	$(MAKE) -C ../build $@$(target-suffix)
