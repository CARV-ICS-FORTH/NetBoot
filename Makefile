# Netboot Application Makefile

# Set SDK_DIR to point to the SDK location (can be overridden from command line or environment)
SDK_DIR ?= ../BareMetal/sdk

# Check if we're building for host test
ifeq ($(MAKECMDGOALS),host)
# Host test build - native compilation
HOST_CC ?= gcc
HOST_CFLAGS = -Wall -Wextra -O2 -g -I src/include -DHOST_TEST -DDEBUG
HOST_LDFLAGS = -lpthread
HOST_SOURCES = $(wildcard src/*.c src/net/*.c src/ether/rawsock_nic.c src/units/*.c)
HOST_OUTPUT = $(CURDIR)/build/netboot_host

.PHONY: all clean test help host host-clean
else
# Bare metal build - SDK-based cross-compilation
include $(SDK_DIR)/build.mk

# Default target (can be overridden: make TARGET=<target>)
TARGET ?= qemu

# Application source files
NETBOOT_SOURCES = $(wildcard src/*.c src/net/*.c src/ether/*.c src/units/*.c)

# Patches for this specific application (overriding platform defaults)
PATCH_SOURCES = $(SDK_DIR)/platform/patches/simple_printf.c
PATCH_SOURCES += $(SDK_DIR)/platform/patches/no_irq.c

ALL_SOURCES = $(NETBOOT_SOURCES) $(PATCH_SOURCES)

# Target-specific CFLAGS
NETBOOT_CFLAGS = $(CFLAGS) -I src/include -I $(SDK_TARGETS_DIR)/$(TARGET) -DDEBUG

# Output files
ELF_OUTPUT = $(CURDIR)/build/bm_netboot.$(TARGET).elf
BIN_OUTPUT = $(CURDIR)/build/bm_netboot.$(TARGET).bin

.PHONY: all clean test help host host-clean
endif

all: $(ELF_OUTPUT) $(BIN_OUTPUT)

help:
	@echo "Netboot Application Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build netboot application (default: TARGET=qemu)"
	@echo "  host             - Build host test version for local testing"
	@echo "  clean            - Clean netboot build artifacts"
	@echo "  host-clean       - Clean host test build artifacts"
	@echo "  test             - Run netboot application on QEMU with TFTP support"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make                          - Build for default target (qemu)"
	@echo "  make TARGET=<target>          - Build for specific target"
	@echo "  make TARGET=<target> test     - Build and run on QEMU with TFTP"
	@echo "  make host                     - Build for host testing"
	@echo ""
	@echo "Environment variables:"
	@echo "  TARGET=<target>  - Specify hardware target (default: qemu)"
	@echo "  SDK_DIR=<path>   - Override SDK location (default: ../../sdk)"
	@echo "  HOST_CC=<cc>     - Specify host compiler (default: gcc)"
	@echo "  V=1              - Verbose build output"

# Build the netboot application
# Links against libplatform_<target>.a which includes yalibc
# Uses PLATFORM_LIB helper from build.mk for proper LTO linking
$(ELF_OUTPUT): $(ALL_SOURCES) $(BUILD_DIR)/libplatform_$(TARGET).a $(LDSCRIPT_DIR)/bmmap.$(TARGET).ld
	@mkdir -p $(CURDIR)/build
	@echo "Building binary for $(TARGET)..."
	$(MSG) "  [GCC]  $@"
	$(Q)$(CC) $(NETBOOT_CFLAGS) $(ALL_SOURCES) $(call PLATFORM_LIB,$(TARGET)) -o $@ $(LOPTS) -T $(LDSCRIPT_DIR)/bmmap.$(TARGET).ld -T unit_sections.ld

# Generate binary from ELF
$(BIN_OUTPUT): $(ELF_OUTPUT)
	$(MSG) "  [BIN]  $@"
	$(Q)$(OBJCOPY) $(CPOPS) $< $@

# Host test build target
host: $(HOST_OUTPUT)

$(HOST_OUTPUT): $(HOST_SOURCES)
	@mkdir -p $(CURDIR)/build
	@echo "Building host test version..."
	$(HOST_CC) $(HOST_CFLAGS) $(HOST_SOURCES) -o $@ $(HOST_LDFLAGS)
	@echo "Host test binary: $@"
	@echo "Run with: sudo ./$(HOST_OUTPUT)"

host-clean:
	@echo "Cleaning host test build artifacts..."
	rm -f $(HOST_OUTPUT)

clean:
	@echo "Cleaning netboot build artifacts..."
	rm -f $(CURDIR)/build/bm_netboot.*.elf
	rm -f $(CURDIR)/build/bm_netboot.*.bin

test: $(BIN_OUTPUT)
	@if [ ! -f $(SDK_TARGETS_DIR)/$(TARGET)/run.sh ]; then \
		echo "Error: No run.sh script found for target $(TARGET)"; \
		exit 1; \
	fi
	@echo "Running netboot for target: $(TARGET)"
	@TFTPROOT=$(CURDIR)/tftp-root ORIGINAL_PWD=$(CURDIR) bash $(SDK_TARGETS_DIR)/$(TARGET)/run.sh $(BIN_OUTPUT)
