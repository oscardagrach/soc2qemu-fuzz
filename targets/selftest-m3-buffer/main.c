/*
 * Buffer-mode fuzz target for mps2-an385 (the board of soc2qemu's selftest-m3).
 * The harness snapshots at main, writes each input into FUZZ_INPUT, and runs until
 * fuzz_end (ok) or fault_handler (crash). Two planted bugs with different fault types, so
 * crash deduplication has something to tell apart:
 *   "SOC!..." executes an undefined instruction  (UsageFault UNDEFINSTR)
 *   "BAD!..." branches without the Thumb bit      (UsageFault INVSTATE)
 * Both escalate to HardFault (configurable fault handlers are not enabled).
 */
#include <stdint.h>

#define FUZZ_INPUT_SIZE 64

volatile uint8_t FUZZ_INPUT[FUZZ_INPUT_SIZE];

__attribute__((noinline)) void fuzz_end(void) { for (;;) { } }
__attribute__((noinline)) void fault_handler(void) { for (;;) { } }

/* Even address: calling it clears the Thumb bit, which M-profile cores cannot execute. */
static void (*const volatile arm_state_target)(void) = (void (*)(void))0x100;

/* One branch per byte so edge coverage can guide the fuzzer to each magic value. */
__attribute__((noinline)) static int parse(const volatile uint8_t *p)
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
    parse(FUZZ_INPUT);
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
