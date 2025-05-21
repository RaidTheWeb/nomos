#
# Nomos Kernel
#

# Directory to be putting binaries and objects when working through source (Jinx best practice, or at least I'd think it would be)
WORK_DIR ?= .

DEST_DIR ?= ./
PREFIX ?=

SOURCE_DIR = src
BIN_DIR = $(WORK_DIR)/bin
BUILD_DIR = $(WORK_DIR)/build

# Kernel output filename.
OUT = nomos

# Kernel output architecture.
ARCH ?= x86_64

HEADERS = $(shell cd $(SOURCE_DIR) && find include -type f -name '*.h') $(shell cd $(SOURCE_DIR) && find include -type f -name '*.hpp')

# Assemble list of sources.
CSOURCES = $(shell cd $(SOURCE_DIR) && find . -type f -name '*.c') $(shell find flanterm -type f -name '*.c')
CXXSOURCES = $(shell cd $(SOURCE_DIR) && find . -type f -name '*.cpp')
ASSOURCES = $(shell cd $(SOURCE_DIR) && find . -type f -name '*.S')
ASMSOURCES = $(shell cd $(SOURCE_DIR) && find . -type f -name '*.asm')

# Assemble list of objects, but with extensions included to aid in specific compile steps later down the line.
OBJECTS = $(addprefix $(BUILD_DIR)-$(ARCH)/,$(CSOURCES:.c=.c.o) $(CXXSOURCES:.cpp=.cpp.o) $(ASSOURCES:.S=.S.o) $(ASMSOURCES:.asm=.asm.o))

# C Compiler
CC ?= cc

# C++ Compiler
CXX ?= cxx

NASM ?= nasm

# C Flags
CFLAGS ?= -g -O2 -pipe

# C++ Flags
CXXFLAGS ?= -g -O2 -pipe

# C Preprocesssor Flags
CPPFLAGS ?= -I $(SOURCE_DIR)/include -I$(SOURCE_DIR)/include/std -Iflanterm/ -DLIMINE_API_REVISION=3 -MMD -MP

# Linker Flags
LDFLAGS ?= -Wl,--build-id=none -nostdlib -static -z max-page-size=0x1000 -Wl,--gc-sections -T linker-$(ARCH).ld

# NASM Flags
NASMFLAGS ?= -F dwarf -g

SHAREDFLAGS ?= \
	-Wall -Wextra -nostdinc -ffreestanding -fno-stack-protector \
	-fno-stack-check -fno-PIC -ffunction-sections -fdata-sections

# Architecture specific.
ifeq ($(ARCH),x86_64)
	SHAREDFLAGS += \
		-m64 -march=x86-64 -mno-80387 -mno-mmx -mno-sse -mno-sse2 -mno-red-zone -mcmodel=kernel

	LDFLAGS += \
		-Wl,-m,elf_x86_64

	NASMFLAGS += \
		-Wall -f elf64
endif

CFLAGS += -std=gnu11 $(SHAREDFLAGS)

# Don't include exceptions, or the C++ runtime
CXXFLAGS += -std=gnu++17 -fno-rtti -fno-exceptions $(SHAREDFLAGS)

.PHONY: all

all: $(BIN_DIR)/$(OUT)-$(ARCH)

$(BIN_DIR)/$(OUT)-$(ARCH): linker-$(ARCH).ld $(OBJECTS)
	mkdir -p "$$(dirname $@)"
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

$(BUILD_DIR)-$(ARCH)/%.c.o: $(SOURCE_DIR)/%.c
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)-$(ARCH)/flanterm/%.c.o: flanterm/%.c
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)-$(ARCH)/%.cpp.o: $(SOURCE_DIR)/%.cpp
	mkdir -p "$$(dirname $@)"
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)-$(ARCH)/%.S.o: $(SOURCE_DIR)/%.S
	mkdir -p "$$(dirname $@)"
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)-$(ARCH)/%.asm.o: $(SOURCE_DIR)/%.asm
	mkdir -p "$$(dirname $@)"
	$(NASM) $(NASMFLAGS) $< -o $@

.PHONY: install
install: all
	install -d "$(DEST_DIR)$(PREFIX)/share/$(OUT)"
	install -m 644 $(BIN_DIR)/$(OUT)-$(ARCH) "$(DEST_DIR)$(PREFIX)/share/$(OUT)/$(OUT)"

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(BUILD_DIR)-$(ARCH)
