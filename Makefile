VERSION   = 0.1

CC        = cc
LD        = $(CC)
CPPFLAGS  = -D_DEFAULT_SOURCE
CFLAGS    = -Wall -Wextra -pedantic -std=c99 $(CPPFLAGS)
LDFLAGS   = -s

.POSIX:
.SUFFIXES: .c .o

HDR = compat.h

SRC = dhcp-client.c compat.c

OBJ = $(SRC:.c=.o)
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
