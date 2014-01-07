all: build/test
.PHONY: all

build/test: build/test.o
	gcc $^ -L ../../lib -lcriu -o $@

build/test.o: test.c
	gcc -c $^ -I ../../lib -o $@

clean:
	rm -rf build
.PHONY: clean
