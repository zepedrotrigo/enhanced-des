# Compiler
CC = gcc

# Compiler Flags
CFLAGS = -O2 -Wall

# Libraries
LIBS = -lssl -lcrypto

# Targets
all: encrypt decrypt

encrypt: encrypt.c edes.c
	$(CC) $(CFLAGS) -o encrypt encrypt.c edes.c $(LIBS)

decrypt: decrypt.c edes.c
	$(CC) $(CFLAGS) -o decrypt decrypt.c edes.c $(LIBS)

clean:
	rm -f encrypt decrypt