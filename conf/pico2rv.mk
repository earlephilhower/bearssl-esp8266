# Configuration for compiling to a Pico from a UNIX system

# We are on a Unix system so we assume a Single Unix compatible 'make'
# utility, and Unix defaults.
include conf/Unix.mk

# We override the build directory.
BUILD = pico2rv

# C compiler, linker, and static library builder.
TOOLCHAIN_PREFIX := riscv32-unknown-elf-
CC := $(TOOLCHAIN_PREFIX)gcc
CFLAGS  = -W -Wall -g -O2 -Wpointer-arith -Wl,-EL -nostdlib -ffunction-sections -fdata-sections -Werror -free -fipa-pta
CFLAGS += -DICACHE_FLASH -DBR_SLOW_MUL15=1 -DPGM_READ_UNALIGNED=0 -DBR_USE_PICO_RAND
CFLAGS += -march=rv32imac_zicsr_zifencei_zba_zbb_zbs_zbkb -mabi=ilp32
LD := $(TOOLCHAIN_PREFIX)ld
AR := $(TOOLCHAIN_PREFIX)ar

# We compile only the static library.
DLL = no
TOOLS = no
TESTS = no
