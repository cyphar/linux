# SPDX-License-Identifier: GPL-2.0

CFLAGS += -Wall -O2 -g
TEST_GEN_PROGS := linkmode_test openat2_test resolve_test rename_attack_test

include ../lib.mk

$(TEST_GEN_PROGS): helpers.c
