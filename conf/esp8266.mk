# Example configuration file for compiling for an Atmel SAM D20 Xplained
# Pro evaluation kit, on a Unix-like system, with a GNU toolchain.

# We are on a Unix system so we assume a Single Unix compatible 'make'
# utility, and Unix defaults.
include conf/Unix.mk

# We override the build directory.
BUILD = esp8266

# C compiler, linker, and static library builder.
TOOLCHAIN_PREFIX := xtensa-lx106-elf-
CC := $(TOOLCHAIN_PREFIX)gcc
CFLAGS = -W -Wall -Os -g -O2 -Wpointer-arith -Wl,-EL -nostdlib -mlongcalls -mno-text-section-literals -ffunction-sections -fdata-sections
CFLAGS += -D__ets__ -DICACHE_FLASH -DESP8266
LD := $(TOOLCHAIN_PREFIX)ld
AR := $(TOOLCHAIN_PREFIX)ar

# We compile only the static library.
DLL = no
TOOLS = no
TESTS = no
