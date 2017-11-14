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

TARGETS := fedora-asan alpine fedora-rawhide phaul
ZDTM_OPTIONS :=

alpine: ZDTM_OPTIONS=-x zdtm/static/binfmt_misc -x zdtm/static/netns-nf -x zdtm/static/sched_policy00 -x zdtm/static/seccomp_strict -x zdtm/static/sigaltstack -x zdtm/static/signalfd00 -x zdtm/static/config_inotify_irmap

$(TARGETS):
	echo 'DOCKER_OPTS="--storage-driver=devicemapper"' > /etc/default/docker
	restart docker
	$(MAKE) -C ../build $@$(target-suffix)
	docker run --rm -it --privileged -v /lib/modules:/lib/modules --tmpfs /run criu-$@ ./scripts/travis/asan.sh $(ZDTM_OPTIONS)

phaul-test:
	echo 'DOCKER_OPTS="--storage-driver=devicemapper"' > /etc/default/docker
	restart docker
	$(MAKE) -C ../build alpine
	docker run --rm -it --privileged -v /lib/modules:/lib/modules --tmpfs /run criu-alpine ./scripts/travis/phaul

docker-test:
	./docker-test.sh

%:
	$(MAKE) -C ../build $@$(target-suffix)
