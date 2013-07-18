.PHONY: all clean

all: libcriu.so

libcriu.so: criu.o
	$(Q) $(CC) $(CFLAGS) -shared -o $@ criu.o

criu.o:
	$(Q) $(CC) $(CFLAGS) -fPIC -c criu.c -I ../include/

clean:
	$(Q) $(RM) -f *.o
	$(Q) $(RM) -f *.so
