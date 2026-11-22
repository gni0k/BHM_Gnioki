# pcapreport - build with:  make            (zlib compression, default)
#                            make NO_ZLIB=1  (zero external dependencies, uncompressed PNG/PDF streams)
#                            make debug      (ASan + UBSan, -O1 -g)

CC      ?= cc
PREFIX  ?= /usr/local
CSTD    := -std=c11
WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes \
           -Wno-missing-field-initializers
CFLAGS  ?= -O2 -g
CPPFLAGS += -D_FILE_OFFSET_BITS=64
LDLIBS  := -lm

ifeq ($(NO_ZLIB),1)
  CPPFLAGS += -DNO_ZLIB
else
  LDLIBS += -lz
endif

SRC := src/main.c src/util.c src/pcap_reader.c src/decode.c src/analyzer.c src/anomaly.c \
       src/zcompat.c src/raster.c src/font_data.c src/chart.c src/png_writer.c src/pdf_writer.c \
       src/report.c
OBJ := $(SRC:src/%.c=build/%.o)
DEP := $(OBJ:.o=.d)
BIN := pcapreport

.PHONY: all clean debug test install uninstall

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c | build
	$(CC) $(CSTD) $(WARN) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

# font_data.c is a large generated table; warnings there are noise
build/font_data.o: src/font_data.c | build
	$(CC) $(CSTD) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

build:
	mkdir -p build

debug:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="-fsanitize=address,undefined"

test: $(BIN)
	./tests/run_tests.sh

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -rf build $(BIN) tests/out

-include $(DEP)
