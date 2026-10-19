# SPDX-License-Identifier: GPL-3.0-only
target.elf: main.c link.ld
	arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -O1 -g -nostdlib -ffreestanding -T link.ld -o $@ main.c
