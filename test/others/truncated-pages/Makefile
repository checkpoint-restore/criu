.PHONY: all run run-cow clean

all: memalloc memalloc_fork

run: all
	./run.sh

run-cow: all
	./run-cow.sh

clean:
	rm -f memalloc memalloc_fork
	rm -rf dump/
