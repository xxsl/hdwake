CC=gcc
LDFLAGS=
CCFLAGS=-O3

# Global

all: hdwake

# Rules
%.o: %.c
	$(CC) -c $(CCFLAGS) $(LDFLAGS) $< -o $@

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)

hdwake: $(OBJECTS)
	$(CC) $(CCFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJECTS) hdwake
