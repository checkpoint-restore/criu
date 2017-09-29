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

TARGETS := fedora-asan alpine fedora-rawhide

$(TARGETS):
	echo 'DOCKER_OPTS="--storage-driver=devicemapper"' > /etc/default/docker
	restart docker
	$(MAKE) -C ../build $@$(target-suffix)
	docker run --rm -it --privileged -v /lib/modules:/lib/modules criu-$@ ./scripts/travis/asan.sh

docker-test:
	./docker-test.sh

%:
	$(MAKE) -C ../build $@$(target-suffix)
