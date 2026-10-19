/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * MMIO-mode fuzz target for mps2-an385. Like soc2qemu's fixture-m3, it enables the
 * unimplemented i2s device and polls its status register (+0x4) for a READY bit; then it reads
 * a 4-byte command from the data register (+0x8) one byte at a time. With
 * `-device soc2qemu-fuzz-mmio` over i2s, every one of those reads returns fuzz input, so the
 * fuzzer has to get past the poll before it can reach the parser. Same planted bugs as
 * selftest-m3-buffer:
 *   "SOC!" executes an undefined instruction  (UsageFault UNDEFINSTR)
 *   "BAD!" branches without the Thumb bit      (UsageFault INVSTATE)
 */
#include <stdint.h>

#define REG(a)  (*(volatile uint32_t *)(a))
#define REG8(a) (*(volatile uint8_t *)(a))
#define I2S 0x40024000u

__attribute__((noinline)) void fuzz_end(void) { for (;;) { } }
__attribute__((noinline)) void fault_handler(void) { for (;;) { } }

/* Even address: calling it clears the Thumb bit, which M-profile cores cannot execute. */
static void (*const volatile arm_state_target)(void) = (void (*)(void))0x100;

/* One branch per byte so edge coverage can guide the fuzzer to each magic value. */
__attribute__((noinline)) static int parse(const uint8_t *p)
{
    if (p[0] == 'S') {
        if (p[1] != 'O') return 1;
        if (p[2] != 'C') return 2;
        if (p[3] != '!') return 3;
        __builtin_trap();
    }
    if (p[0] == 'B') {
        if (p[1] != 'A') return 4;
        if (p[2] != 'D') return 5;
        if (p[3] != '!') return 6;
        arm_state_target();
    }
    return 0;
}

int main(void)
{
    uint8_t cmd[4];

    REG(I2S) = 0x1234;                  /* "enable" */
    while (!(REG(I2S + 4) & 1)) { }     /* wait for READY */
    for (int i = 0; i < 4; i++)
        cmd[i] = REG8(I2S + 8);
    parse(cmd);
    fuzz_end();
    return 0;
}

void reset(void)
{
    main();
    for (;;) { }
}

extern uint32_t _stack_top;
__attribute__((section(".vectors"))) const void *vectors[] = {
    &_stack_top,
    reset,
    fault_handler,  /* NMI */
    fault_handler,  /* HardFault */
    fault_handler,  /* MemManage */
    fault_handler,  /* BusFault */
    fault_handler,  /* UsageFault */
};
