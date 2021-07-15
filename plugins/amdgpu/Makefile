all: dummy_plugin.so

dummy_plugin.so: dummy_plugin.c
	gcc -g -Werror -D _GNU_SOURCE -Wall -shared -nostartfiles dummy_plugin.c -o dummy_plugin.so -iquote ../../../criu/include -iquote ../../criu/include -fPIC

clean:
	$(Q) $(RM) dummy_plugin.so
install:
	$(Q) mkdir -p $(PLUGINDIR)
	$(Q) install -m 644 dummy_plugin.so $(PLUGINDIR)

uninstall:
	$(Q) $(RM) $(PLUGINDIR)/dummy_plugin.so
