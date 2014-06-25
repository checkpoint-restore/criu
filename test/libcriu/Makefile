all: test_sub test_self
.PHONY: all

run: all
	./run.sh

test_sub: test_sub.o
	gcc $^ -L ../../lib -lcriu -o $@

test_sub.o: test_sub.c
	gcc -c $^ -I ../../lib -o $@

test_self: test_self.o
	gcc $^ -L ../../lib -lcriu -o $@

test_self.o: test_self.c
	gcc -c $^ -I ../../lib -o $@

clean:
	rm -rf test_sub test_sub.o test_self test_sub.o
.PHONY: clean
