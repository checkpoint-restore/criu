ifeq ($(ARCH),)
        ARCH := x86
endif

# FIXME -- generate common symlink in compel/uapi
COMMON_IDIR	:= ../../../include
COMPEL_IDIR	:= ../../../compel/include/uapi
COMPEL_LIBRARY	:= ../../../compel/libcompel.a

all: victim spy

clean:
	rm -f victim
	rm -f spy

victim: victim.c
	gcc -o $@ $^

spy: spy.c $(COMPEL_LIBRARY)
	gcc -Werror -I$(COMPEL_IDIR) -I$(COMMON_IDIR) -o $@ $^
