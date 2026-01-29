# Image Tools Makefile

# Parser test executable
TEST_PARSER = test_parser

# Source files (relative to parent directory)
SRC_DIR = ../src
SRCS = test_parser.c \
       $(SRC_DIR)/image_parser.c \
       $(SRC_DIR)/lz4.c \
       $(SRC_DIR)/units/self.c

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -I$(SRC_DIR)/include -DHOST_TEST -DDEBUG

all: $(TEST_PARSER)

$(TEST_PARSER): $(SRCS)
	@echo "Building parser test..."
	$(CC) $(CFLAGS) $(SRCS) -o $@
	@echo "Done! Run with: ./$(TEST_PARSER) [path/to/boot.img]"

clean:
	rm -f $(TEST_PARSER)

test: $(TEST_PARSER)
	@echo "Running parser test..."
	./$(TEST_PARSER) ../tftp-root/boot.img
	@echo ""
	@echo "Verifying output files..."
	@echo "=== FSBL Checksums ==="
	@md5sum ../tftp-root/boot.bin /tmp/part0.bin || true
	@echo ""
	@echo "=== DTB Checksums ==="
	@md5sum ../tftp-root/boot.dtb /tmp/part1.bin || true

.PHONY: all clean test
