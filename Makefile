VERSION   = 0.1

CC        = g++
LD        = $(CC)
CPPFLAGS  = -D_DEFAULT_SOURCE
CFLAGS    = -Wall -Wextra -pedantic -std=c99 $(CPPFLAGS)
LDFLAGS   = -s

.POSIX:
.SUFFIXES: .cpp .o

HDR = compat.hpp

SRC = dhcp-client.cpp compat.cpp

OBJ = $(SRC:.cpp=.o)
BIN = dhcp-client
MAN = $(BIN).1

all: options $(BIN)

options:
	@echo dhcp-client build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

$(BIN): $(OBJ)
	@$(LD) -o $@ $(OBJ) $(LDFLAGS)

.c.o:
	@echo CC $<
	@$(CC) -c -o $@ $< $(CFLAGS)

clean:
	@echo cleaning
	@rm -f $(BIN) $(OBJ) util.a

.PHONY: all options clean
