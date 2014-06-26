TESTS += test_sub 
TESTS += test_self
TESTS += test_notify
TESTS += test_iters

all: $(TESTS)

run: all
	./run.sh

define genb
$(1): $(1).o lib.o
	gcc $$^ -L ../../lib -lcriu -o $$@
endef

$(foreach t, $(TESTS), $(eval $(call genb, $(t))))

%.o: %.c
	gcc -c $^ -I../../lib/ -o $@ -Werror

clean:
	rm -rf $(TESTS) $(TESTS:%=%.o) lib.o

.PHONY: clean
.PHONY: all
