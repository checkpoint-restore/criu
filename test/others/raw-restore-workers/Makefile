ROOT := ../../..
CFLAGS += -O2 -g -Wall -Werror -fno-strict-aliasing -ffunction-sections -fdata-sections -mshstk
CPPFLAGS += -DCONFIG_X86_64 -DCONFIG_COMPAT -DCR_NOGLIBC -D_GNU_SOURCE
CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
CPPFLAGS += -Icompel/include/uapi -iquote criu/include -iquote include -iquote images
CPPFLAGS += -iquote criu/arch/x86/include -iquote .

.PHONY: check clean workers_test
check: workers_test
	./workers_test

workers_test: workers_test.c $(ROOT)/criu/pie/restorer.c
	cd $(ROOT) && $(CC) $(CPPFLAGS) $(CFLAGS) $(USERCFLAGS) \
		test/others/raw-restore-workers/workers_test.c \
		compel/arch/x86/plugins/std/syscalls-64.o -Wl,--gc-sections \
		-o test/others/raw-restore-workers/workers_test

clean:
	$(RM) workers_test
