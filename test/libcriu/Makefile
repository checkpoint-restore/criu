all: build/test test_sub
.PHONY: all

run: all
	./run.sh

test_sub: test_sub.o
	gcc $^ -L ../../lib -lcriu -o $@

test_sub.o: test_sub.c
	gcc -c $^ -I ../../lib -o $@

build/test: build/test.o
	gcc $^ -L ../../lib -lcriu -o $@

build/test.o: test.c
	gcc -c $^ -I ../../lib -o $@

clean:
	rm -rf build test_sub test_sub.o
.PHONY: clean
