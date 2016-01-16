INCLUDES = -I../lib -I../simplelogger
CCFLAGS = -g -O2 -fpic
CCC = gcc
LIB = ../lib/provenancelib.a ../simplelogger/simplog.a -lpthread

.SUFFIXES: .c

all:
	$(CCC) $(INCLUDES) audit.c $(LIB) -o audit.o $(CCFLAGS)

install:
	cp --force ./audit.o /usr/bin/relay-audit
	mkdir -p /var/relay
	cp --force ./audit.service /etc/systemd/system/audit.service
	systemctl enable audit.service

clean:
	rm -f audit.o
