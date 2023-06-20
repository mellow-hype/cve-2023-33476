# Basic flags
CC := clang
CFLAGS = -g -O0
LIBS := -lsqlite3 -lexif -ljpeg -lvorbis -lavformat -lavutil -logg -lid3tag -lFLAC

BASEDIR = .
SRCDIR = $(BASEDIR)/minidlna-1.3.0
FUZZSRC = $(BASEDIR)/fuzzers
SRCS := $(wildcard $(SRCDIR)/*.c)
SRCS += $(wildcard $(SRCDIR)/tagutils/*.c)

all: config fuzz_http

clean:
	cd $(SRCDIR); make clean

##################################################
# LIBFUZZER BUILD
# Build the minidlna source to create the required object files
fuzz_http: CFLAGS += -fsanitize=fuzzer,address
config: $(SRCS)
	cd $(SRCDIR); \
	./configure CC=$(CC) CFLAGS="$(CFLAGS)"; \
	make clean; cp minidlna.c minidlna.c.ORIG

fuzz_http: CFLAGS += -fsanitize=fuzzer,address
fuzz_http:
	cp $(FUZZSRC)/fuzz_harness.c $(SRCDIR)/minidlna.c
	cd $(SRCDIR); make CC=$(CC) CFLAGS="$(CFLAGS)" minidlnad
	cp $(SRCDIR)/minidlnad $(SRCDIR)/fuzzer_http

##################################################

