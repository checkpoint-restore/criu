ifndef ____nmk_defined__include

ifndef ____nmk_defined__msg
        include $(__nmk_dir)msg.mk
endif

#
# Common vars.
SUBARCH := $(shell uname -m | sed       \
                -e s/i.86/x86/          \
                -e s/x86_64/x86/        \
                -e s/sun4u/sparc64/     \
                -e s/arm.*/arm/         \
                -e s/sa110/arm/         \
                -e s/s390x/s390/        \
                -e s/parisc64/parisc/   \
                -e s/ppc64.*/ppc64/     \
                -e s/mips.*/mips/       \
                -e s/sh[234].*/sh/      \
                -e s/aarch64.*/arm64/)

ARCH		?= $(SUBARCH)
SRCARCH 	:= $(ARCH)

export SUBARCH ARCH SRCARCH

ifndef ____nmk_defined__tools
        include $(__nmk_dir)tools.mk
endif

# Do not use make's built-in rules and variables
# (this increases performance and avoids hard-to-debug behaviour).
MAKEFLAGS += -rR
export MAKEFLAGS

# Avoid funny character set dependencies.
unexport LC_ALL
LC_COLLATE=C
LC_NUMERIC=C
export LC_COLLATE LC_NUMERIC

# Avoid interference with shell env settings.
unexport GREP_OPTIONS

# Shorthand for build.
build := -r -R -f $(__nmk_dir)main.mk makefile=Makefile obj
export build

# With specified Makefile
build-as = -r -R -f $(__nmk_dir)main.mk makefile=$(1) obj=$(2)
export build-as

#
# Footer.
$(__nmk_dir)scripts/include.mk:
	@true
____nmk_defined__include = y
endif
