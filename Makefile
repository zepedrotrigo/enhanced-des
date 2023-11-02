# Compiler
CC = gcc

# Compiler Flags
CFLAGS = -O2 -Wall

# Libraries
LIBS = -lssl -lcrypto

# Directories
SRC_DIR = src/c
BIN_DIR = bin

# Targets
all: $(BIN_DIR)/encrypt $(BIN_DIR)/decrypt $(BIN_DIR)/speed

$(BIN_DIR)/encrypt: $(SRC_DIR)/encrypt.c $(SRC_DIR)/edes.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/encrypt $(SRC_DIR)/encrypt.c $(SRC_DIR)/edes.c $(LIBS)

$(BIN_DIR)/decrypt: $(SRC_DIR)/decrypt.c $(SRC_DIR)/edes.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/decrypt $(SRC_DIR)/decrypt.c $(SRC_DIR)/edes.c $(LIBS)

$(BIN_DIR)/speed: $(SRC_DIR)/speed.c $(SRC_DIR)/edes.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/speed $(SRC_DIR)/speed.c $(SRC_DIR)/edes.c $(LIBS)

clean:
	rm -f $(BIN_DIR)/encrypt $(BIN_DIR)/decrypt $(BIN_DIR)/speed
