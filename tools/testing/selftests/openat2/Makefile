# SPDX-License-Identifier: GPL-2.0

CFLAGS += -Wall -O2 -g
TEST_GEN_PROGS := linkmode_test resolve_test rename_attack_test

include ../lib.mk

$(OUTPUT)/linkmode_test: linkmode_test.c helpers.o
$(OUTPUT)/rename_attack_test: rename_attack_test.c helpers.o
$(OUTPUT)/resolve_test: resolve_test.c helpers.o

EXTRA_CLEAN = helpers.o $(wildcard /tmp/ksft-openat2-*)
