# SPDX-License-Identifier: GPL-2.0
#
# Kbuild file: when scripts/Makefile.build descends into M=$(CURDIR), it
# prefers a `Kbuild` over `Makefile`, which avoids the KERNELRELEASE-guard
# ambiguity that can make obj-m disappear during external module builds.

obj-m += selinux_status_repair.o

ccflags-y += -Wno-unused-function
