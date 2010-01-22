OBJS=bogom.o conf.o
BIN=bogom
MAN=bogom.8

# default instalation prefix
PREFIX=/usr/local

# edit to fit your system configuration
CPPFLAGS=
CFLAGS+=-Wall -g
LDFLAGS=
LIBS+=-lmilter -lpthread

all: $(BIN)

bogom.o: milter.c conf.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c milter.c -o bogom.o
conf.o: conf.c conf.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c conf.c -o conf.o

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $(BIN) $(OBJS) $(LIBS)

install: $(BIN) $(MAN)
	cp -f $(BIN) $(PREFIX)/libexec
	cp -f $(MAN) $(PREFIX)/man/man8

clean:
	rm -f $(BIN) $(OBJS)

