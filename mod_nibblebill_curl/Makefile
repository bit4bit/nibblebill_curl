
FS_INCLUDES=/usr/local/include/freeswitch
FS_MODULES=/usr/local/lib/freeswitch/mod

MODNAME = mod_nibblebill_curl.so
MODOBJ = mod_nibblebill_curl.o
MODCFLAGS = -Wall -Werror
MODLDFLAGS = -lssl


CC=gcc
CFLAGS=-fPIC -g -ggdb -I/usr/local/include -I$(FS_INCLUDES) $(MODCFLAGS)
LDFLAGS=-Wl,-Bdynamic $(MODLDFLAGS)

.PHONY: all
all: $(MODNAME)

$(MODNAME): $(MODOBJ)
        @$(CC) -shared -o $@ $(MODOBJ) $(LDFLAGS)

.c.o: $<
        @$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
        rm -f $(MODNAME) $(MODOBJ)

.PHONY: install
install: $(MODNAME)
        install -d $(FS_MODULES)
        install $(MODNAME) $(FS_MODULES)
