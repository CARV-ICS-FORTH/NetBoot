# Image Tools Makefile

VERIFY_CONTAINER = verify_container

SRC_DIR = ../src
SRCS = verify_container.c \
       $(SRC_DIR)/image_parser.c \
       $(SRC_DIR)/lz4.c \
       $(SRC_DIR)/units/self.c \
       $(SRC_DIR)/crypto/sha512.c \
       $(SRC_DIR)/crypto/ed25519.c

CC     = gcc
CFLAGS = -Wall -Wextra -O2 -g \
         -I$(SRC_DIR)/include \
         -DHOST_TEST -DDEBUG
LDFLAGS = -lssl -lcrypto

all: $(VERIFY_CONTAINER)

$(VERIFY_CONTAINER): $(SRCS)
	@echo "Building container verifier..."
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)
	@echo "Done! Run with: ./$(VERIFY_CONTAINER) [path/to/boot.img]"
	@echo "       or:      ./$(VERIFY_CONTAINER) -d [path/to/boot.img]  (dump partitions to /tmp/partN.bin)"
	@echo "       or:      ./$(VERIFY_CONTAINER) -t [path/to/boot.img]  (streaming parser test)"

clean:
	rm -f $(VERIFY_CONTAINER) test_key.pem test_key.pub boot_signed.img

test: $(VERIFY_CONTAINER)
	@echo "Running parser test (unsigned)..."
	./$(VERIFY_CONTAINER) -t ../tftp-root/boot.img
	@echo ""
	@echo "Verifying output files..."
	@echo "=== FSBL Checksums ==="
	@md5sum ../tftp-root/boot.bin /tmp/part0.bin || true
	@echo ""
	@echo "=== DTB Checksums ==="
	@md5sum ../tftp-root/boot.dtb /tmp/part1.bin || true

test-signed: $(VERIFY_CONTAINER)
	@echo "Generating test Ed25519 key..."
	python3 build_container.py --keygen test_key.pem
	@echo ""
	@echo "Building signed image..."
	python3 build_container.py \
		../tftp-root/boot.bin ../tftp-root/boot.dtb boot_signed.img \
		--sign test_key.pem
	@echo ""
	@echo "Inspecting signed image..."
	./$(VERIFY_CONTAINER) boot_signed.img
	@echo ""
	@echo "Running parser test on signed image..."
	./$(VERIFY_CONTAINER) -t boot_signed.img
	@echo ""
	@echo "Verifying output files..."
	@echo "=== FSBL Checksums ==="
	@md5sum ../tftp-root/boot.bin /tmp/part0.bin || true
	@echo ""
	@echo "=== DTB Checksums ==="
	@md5sum ../tftp-root/boot.dtb /tmp/part1.bin || true

.PHONY: all clean test test-signed
