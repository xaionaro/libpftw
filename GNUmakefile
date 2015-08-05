
DESTDIR ?= 
PREFIX  ?= /usr
COMPRESS_MAN ?= yes
STRIP_BINARY ?= yes
EXAMPLES ?= yes

CSECFLAGS ?= -fstack-protector-all -Wall --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -fstack-check -DPARANOID -std=gnu99
CFLAGS ?= -pipe -O2
CFLAGS += $(CSECFLAGS) -fpic
DEBUGCFLAGS ?= -pipe -Wall -ggdb3 -export-dynamic -Wno-error=unused-variable -O0 -pipe $(CSECFLAGS) -fpic

CARCHFLAGS ?= -march=native

LIBS :=
LDSECFLAGS ?= -Xlinker -zrelro
LDFLAGS += $(LDSECFLAGS) -pthread -shared
INC := $(INC)

INSTDIR = $(DESTDIR)$(PREFIX)

objs=\
pftw.o\

binary=libpftw.so

.PHONY: doc

all: $(objs)
	$(CC) $(CARCHFLAGS) $(CFLAGS) $(LDFLAGS) $(objs) $(LIBS) -o $(binary)

%.o: %.c
	$(CC) $(CARCHFLAGS) $(CFLAGS) $(INC) $< -c -o $@

debug:
	$(CC) $(CARCHFLAGS) -D_DEBUG_SUPPORT $(DEBUGCFLAGS) $(INC) $(LDFLAGS) *.c $(LIBS) -o $(binary)


clean:
	rm -f $(binary) *.o test

distclean: clean

doc:
	doxygen .doxygen

install:
	install -d "$(INSTDIR)/bin" "$(INSTDIR)/share/man/man3"
ifeq ($(STRIP_BINARY),yes)
	strip --strip-unneeded -R .comment -R .GCC.command.line -R .note.gnu.gold-version $(binary)
endif
	install -m 755 $(binary) "$(INSTDIR)"/bin/
	install -m 644 man/man3/pftw.3 "$(INSTDIR)"/share/man/man3/
ifeq ($(COMPRESS_MAN),yes)
	rm -f "$(INSTDIR)"/share/man/man3/pftw.3.gz
	gzip  "$(INSTDIR)"/share/man/man3/pftw.3
endif

deinstall:
	rm -f "$(INSTDIR)"/bin/$(binary)

test: all
	$(CC) -O3 test.c -lpftw -L. -o test

debugtest: debug
	$(CC) -O0 -ggdb test.c -lpftw -L. -o test


dotest: test
	LD_LIBRARY_PATH=. ./test

