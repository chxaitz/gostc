# Makefile for gostc 1.0.0
VERBOSE=1

# Toolchain configuration
CROSS_COMPILE = 
# CROSS_COMPILE = /c/gcc/bin/arm-none-eabi-
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
RANLIB = $(CROSS_COMPILE)ranlib
SIZE = $(CROSS_COMPILE)size

# CPU architecture configuration
CPU = cortex-m3
# ARCH_FLAGS = -mcpu=$(CPU) -mthumb -mfloat-abi=soft
ARCH_FLAGS =

# Optimization options
OPTIMIZATION = -Os -ffunction-sections -fdata-sections

# Warning options
WARNINGS = -Wall -Wextra -Wstrict-prototypes -Wshadow

# GmSSL specific macro definitions
DEFINES = \
	-DNDEBUG 

# Include paths
INCLUDES = \
	-I.

# Complete compilation flags
CFLAGS = $(ARCH_FLAGS) $(OPTIMIZATION) $(WARNINGS) $(DEFINES) $(INCLUDES)

# All source files
ALL_SOURCES = \
	src/gost_client.c \
	src/gost_relay.c \
	src/socks5_client.c 

# Convert to object files
BUILD_DIR = build
OBJECTS = $(addprefix $(BUILD_DIR)/,$(ALL_SOURCES:.c=.o))

# Target library files
TARGET_LIB = lib/libgostc.a
TARGET_BIN = bin/main

# Default target
all: prepare $(TARGET_LIB)

# Prepare directories
prepare:
	@mkdir -p lib
	@mkdir -p build

# Compile static library
$(TARGET_LIB): $(OBJECTS)
	@echo "Archiving $(TARGET_LIB)..."
	$(AR) rcs $@ $(OBJECTS)
	$(RANLIB) $@
	@echo "=== Library Size ==="
	$(SIZE) -t $@
	@echo "===================="

# Generic compilation rule
$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir build/$*)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Generate header dependencies (optional)
DEPENDENCIES = $(OBJECTS:.o=.d)
-include $(DEPENDENCIES)

$(BUILD_DIR)/%.d: %.c
	@mkdir -p $(dir build/$*)
	@$(CC) $(CFLAGS) -MM -MT build/$*.o $< > build/$*.d

# Clean
clean:
	rm -rf build lib
	find . -name "*.o" -delete
	find . -name "*.d" -delete
	find . -name "*.a" -delete

.PHONY: all prepare clean install