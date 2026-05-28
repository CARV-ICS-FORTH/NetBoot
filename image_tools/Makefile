# Image Tools Makefile

TARGET = nbimgt

SRC_DIR = ../src
SRCS = nbimgt.c \
       res.c \
       crypto_ops.c \
       key_file.c \
       partition.c \
       container.c \
       $(SRC_DIR)/image_parser.c \
       $(SRC_DIR)/lz4.c \
       $(SRC_DIR)/units/self.c \
       $(SRC_DIR)/crypto/sha512.c \
       $(SRC_DIR)/crypto/ed25519.c

CC     = gcc
CFLAGS = -Wall -Wextra -O2 -g \
         -D_GNU_SOURCE \
         -I$(SRC_DIR)/include \
         -DHOST_TEST -DDEBUG
LDFLAGS = -lssl -lcrypto -llz4

all: $(TARGET)

$(TARGET): $(SRCS)
	@echo "Building $(TARGET)..."
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)
	@echo "Done! Run with:"
	@echo "  ./$(TARGET) build [--sign KEY.pem] FSBL DTB [OUTPUT]"
	@echo "  ./$(TARGET) verify [--dump] [--test-parser] IMAGE"
	@echo "  ./$(TARGET) keygen KEY.pem"

clean:
	rm -f $(TARGET) test_key.pem test_key.pem.pub boot_signed.img \
	      ../tftp-root/boot.img

test: $(TARGET)
	@echo "Building unsigned image..."
	./$(TARGET) build ../tftp-root/boot.bin ../tftp-root/boot.dtb \
		../tftp-root/boot.img
	@echo ""
	@echo "Running parser test (unsigned)..."
	./$(TARGET) verify --test-parser ../tftp-root/boot.img
	@echo ""
	@echo "Verifying output files..."
	@echo "=== FSBL Checksums ==="
	@md5sum ../tftp-root/boot.bin /tmp/part0.bin || true
	@echo ""
	@echo "=== DTB Checksums ==="
	@md5sum ../tftp-root/boot.dtb /tmp/part1.bin || true

test-signed: $(TARGET)
	@echo "Generating test Ed25519 key..."
	./$(TARGET) keygen test_key.pem
	@echo ""
	@echo "Building signed image..."
	./$(TARGET) build --sign test_key.pem \
		../tftp-root/boot.bin ../tftp-root/boot.dtb boot_signed.img
	@echo ""
	@echo "Inspecting signed image..."
	./$(TARGET) verify boot_signed.img
	@echo ""
	@echo "Running parser test on signed image..."
	./$(TARGET) verify --test-parser boot_signed.img
	@echo ""
	@echo "Verifying output files..."
	@echo "=== FSBL Checksums ==="
	@md5sum ../tftp-root/boot.bin /tmp/part0.bin || true
	@echo ""
	@echo "=== DTB Checksums ==="
	@md5sum ../tftp-root/boot.dtb /tmp/part1.bin || true

.PHONY: all clean test test-signed
