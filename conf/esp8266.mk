# Configuration for compiling to an ESP8266 from a UNIX system

# We are on a Unix system so we assume a Single Unix compatible 'make'
# utility, and Unix defaults.
include conf/Unix.mk

# We override the build directory.
BUILD = esp8266

# C compiler, linker, and static library builder.
# TODO - when GCC jump tables are moved to inline, remove the -fno-jump-tables.  This setting saves ~1.3KB RAM at the cose of 1.3KB of flash, but is slower by a bit
TOOLCHAIN_PREFIX := xtensa-lx106-elf-
CC := $(TOOLCHAIN_PREFIX)gcc
CFLAGS = -W -Wall -g -O2 -Wpointer-arith -Wl,-EL -nostdlib -mlongcalls -mno-text-section-literals -ffunction-sections -fdata-sections -fno-jump-tables -Werror
CFLAGS += -D__ets__ -DICACHE_FLASH -DESP8266
LD := $(TOOLCHAIN_PREFIX)ld
AR := $(TOOLCHAIN_PREFIX)ar

# We compile only the static library.
DLL = no
TOOLS = no
TESTS = no
