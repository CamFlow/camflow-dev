SRC = ./build/thpool.c
OBJ = $(SRC:.c=.o)
OUT = thpool.a
INCLUDES = -I./build
CCFLAGS = -g -O2 -fpic
CCC = gcc
LDFLAGS = -g

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
	cd ./build && git init && git remote add origin $(git_source) && git fetch origin && git checkout -b master --track origin/master
	cp --force ./build/thpool.h ./thpool.h
