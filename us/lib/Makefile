SRC = provenancelib.c
OBJ = $(SRC:.c=.o)
OUT = provenance.a
INCLUDES = -I. -I../threadpool
CCFLAGS = -g -O2 -fpic -std=c11
CCC = gcc
LDFLAGS = -g

.SUFFIXES: .c

all: static

static: $(OUT)

.c.o:
	$(CCC) $(INCLUDES) $(CCFLAGS) $(EXTRACCFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	ar rcs provenance.a $(OBJ)
	ar -M <provenancelib.mri

clean:
	rm -f $(OBJ) $(OUT)
