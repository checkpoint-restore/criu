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

TARGETS := alpine fedora-rawhide centos
ZDTM_OPTIONS :=

alpine: ZDTM_OPTIONS=-x zdtm/static/binfmt_misc -x zdtm/static/netns-nf -x zdtm/static/sched_policy00 -x zdtm/static/seccomp_strict -x zdtm/static/sigaltstack -x zdtm/static/signalfd00 -x zdtm/static/config_inotify_irmap

define DOCKER_JSON
{
	"storage-driver": "devicemapper"
}
endef

export DOCKER_JSON
$(TARGETS):
	echo "$$DOCKER_JSON" > /etc/docker/daemon.json
	systemctl restart docker
	$(MAKE) -C ../build $@$(target-suffix)
	docker run --env-file docker.env --rm -it --privileged -v /lib/modules:/lib/modules --tmpfs /run criu-$@ scripts/travis/travis-tests

fedora-asan:
	echo "$$DOCKER_JSON" > /etc/docker/daemon.json
	systemctl restart docker
	$(MAKE) -C ../build $@$(target-suffix)
	docker run --rm -it --privileged -v /lib/modules:/lib/modules --tmpfs /run criu-$@ ./scripts/travis/asan.sh $(ZDTM_OPTIONS)

docker-test:
	./docker-test.sh

%:
	$(MAKE) -C ../build $@$(target-suffix)
