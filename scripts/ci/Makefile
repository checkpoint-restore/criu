local:
	./run-ci-tests.sh
.PHONY: local

after_success:
	./ci-after-success.sh
.PHONY: after_success

target-suffix =
ifdef CLANG
	target-suffix = -clang
endif

TARGETS := alpine fedora-rawhide archlinux
ZDTM_OPTS :=
UNAME := $(shell uname -m)
export UNAME
CONTAINER_RUNTIME := docker
export CONTAINER_RUNTIME

alpine: ZDTM_OPTS=-x zdtm/static/binfmt_misc -x zdtm/static/sched_policy00

ifeq ($(GITHUB_ACTIONS),true)
	# GitHub Actions does not give us a real TTY and errors out with
	# 'the input device is not a TTY' if using '-t'
	CONTAINER_TERMINAL := -i
else
	CONTAINER_TERMINAL := -it
endif

export CONTAINER_TERMINAL

# Here we assume that any CPU architecture besides x86_64 is running in containers
# that may not support running docker with '--privileged'.
ifeq ($(UNAME),x86_64)
	CONTAINER_OPTS := --rm $(CONTAINER_TERMINAL) --privileged --userns=host --cgroupns=host -v /lib/modules:/lib/modules --tmpfs /run
else
	CONTAINER_OPTS := --rm -v /lib/modules:/lib/modules --tmpfs /run
endif

ifeq ($(CONTAINER_RUNTIME),podman)
	# Podman limits the number of processes in a container using cgroups.
	# Disable it as it breaks the thread-bomb test
	CONTAINER_OPTS += --pids-limit=0
endif

export ZDTM_OPTS

$(TARGETS):
	$(MAKE) -C ../build $@$(target-suffix)
	$(CONTAINER_RUNTIME) run --env-file docker.env -v `pwd`/../../:/criu $(if $(ZDTM_OPTS),-e ZDTM_OPTS) $(CONTAINER_OPTS) criu-$@ scripts/ci/run-ci-tests.sh

fedora-asan:
	$(MAKE) -C ../build $@$(target-suffix)
	$(CONTAINER_RUNTIME) run $(CONTAINER_OPTS) -v `pwd`/../../:/criu criu-$@ ./scripts/ci/asan.sh $(ZDTM_OPTS)

docker-test:
	./docker-test.sh

podman-test:
	./podman-test.sh

java-test:
	./java-test.sh

setup-vagrant:
	./vagrant.sh setup

vagrant-fedora-no-vdso: setup-vagrant
	./vagrant.sh fedora-no-vdso

vagrant-fedora-rawhide: setup-vagrant
	./vagrant.sh fedora-rawhide

vagrant-fedora-non-root: setup-vagrant
	./vagrant.sh fedora-non-root

.PHONY: setup-vagrant vagrant-fedora-no-vdso vagrant-fedora-rawhide vagrant-fedora-non-root

check-commit:
	($(MAKE) -j $$(nproc) -C ../.. && \
		echo "Commit $$(git rev-parse --short HEAD) built successfully") || \
		(echo "Build failed for $$(git rev-list -n 1 --pretty HEAD)" && \
		exit 1)

.PHONY: check-commit

loongarch64-qemu-test:
	./loongarch64-qemu-test.sh

.PHONY: loongarch64-qemu-test

%:
	$(MAKE) -C ../build $@$(target-suffix)
