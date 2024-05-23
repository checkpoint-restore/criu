CC = gcc
CFLAGS = -c -fPIC -ldl

SRC = libfault.c
OBJ = $(SRC:.c=.o)

LIB = libfault.so

.PHONY: all clean run

all: $(LIB)

$(LIB): $(OBJ)
	$(CC) -shared -o $(LIB) $(OBJ)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) $<

clean:
	rm -f $(OBJ) $(LIB)

