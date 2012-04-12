all: foo1.o foo2.o foo3.o foo4.o
	echo "Done"

%.o: %.c
	gcc -c $< -o $@

foo%.c: tmpl.c
	cp $< $@

clean:
	rm -f *.o
