TESTS += test_sub 
TESTS += test_self
TESTS += test_notify
TESTS += test_iters
TESTS += test_errno

all: $(TESTS)
.PHONY: all

run: all
	./run.sh
.PHONY: run

define genb
$(1): $(1).o lib.o
	gcc $$^ -L ../../../../criu/lib/c/ -L ../../../../criu/images/ -lcriu -o $$@
endef

$(foreach t, $(TESTS), $(eval $(call genb, $(t))))

%.o: %.c
	gcc -c $^ -I../../../../criu/lib/c/ -I../../../../criu/images/ -o $@ -Werror

clean:
	rm -rf $(TESTS) $(TESTS:%=%.o) lib.o
.PHONY: clean
