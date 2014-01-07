all: job
.PHONY: all

%.o: %.c
	gcc -c $< -o $@

job: job.o
	gcc -o $@ job.o

clean:
	rm -f *.o job
.PHONY: clean
