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
OPTIMIZATION = -fsanitize=address -fno-omit-frame-pointer -g -Os -ffunction-sections -fdata-sections

# Warning options
WARNINGS = -Wall -Wextra -Wstrict-prototypes -Wshadow

# Specific macro definitions
DEFINES = \
	-DNDEBUG 

# Include paths
INCLUDES = \
	-I. \
	-Iinclude \
	-I3rd_unix

# Complete compilation flags
CFLAGS = $(ARCH_FLAGS) $(OPTIMIZATION) $(WARNINGS) $(DEFINES) $(INCLUDES)

LDFLAGS = \
    -L3rd_unix/lib -llwipcommon \
	-lmbedcrypto -lmbedtls -lmbedx509 -lpthread 

# All source files
ALL_SOURCES = \
	3rd_unix/tapif.c \
	3rd_unix/sys_arch.c \
	tests/unit/test_tls.c
# 	src/gostc_api.c \
# 	src/gostc_config_mgr.c \
# 	src/gostc_dns_filter.c \
# 	src/gostc_lwip_intercept.c \
# 	src/gostc_memory_pool.c \
# 	src/gostc_os_linux.c \
# 	src/gostc_tls_engine.c \
# 	src/re.c
	

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

# Compile binary
bin: $(TARGET_BIN)

$(TARGET_BIN): $(OBJECTS)
	@echo "Building $(TARGET_BIN)..."
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)
	@echo "=== Binary Size ==="
	$(SIZE) -t $@
	@echo "===================="

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