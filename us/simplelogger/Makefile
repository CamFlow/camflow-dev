SRC = ./build/simplog.c
OBJ = $(SRC:.c=.o)
OUT = simplog.a
INCLUDES = -I./build
CCFLAGS = -g -O2 -fpic
CCC = gcc
LDFLAGS = -g
GIT_SOURCE=https://github.com/ntpeters/SimpleLogger.git

.SUFFIXES: .c

all: static

static: $(OUT)

.c.o:
	$(CCC) $(INCLUDES) $(CCFLAGS) $(EXTRACCFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	ar rcs $(OUT) $(OBJ)

clean:
	rm -f $(OBJ) $(OUT) $(DYN)

prepare:
	mkdir -p build
	cd ./build && git init && git remote add origin $(GIT_SOURCE) && git fetch origin && git checkout -b master --track origin/master
	cp --force ./build/simplog.h ./simplog.h
