/*
 * Buffer-mode fuzz target for mps2-an385 (the board of soc2qemu's selftest-m3).
 * The harness snapshots at main, writes each input into FUZZ_INPUT, and runs until
 * fuzz_end (ok) or fault_handler (crash). Planted bug: an input starting with "SOC!"
 * executes an undefined instruction (UsageFault, escalated to HardFault).
 */
#include <stdint.h>

#define FUZZ_INPUT_SIZE 64

volatile uint8_t FUZZ_INPUT[FUZZ_INPUT_SIZE];

__attribute__((noinline)) void fuzz_end(void) { for (;;) { } }
__attribute__((noinline)) void fault_handler(void) { for (;;) { } }

/* One branch per byte so edge coverage can guide the fuzzer to the magic value. */
__attribute__((noinline)) static int parse(const volatile uint8_t *p)
{
    if (p[0] != 'S') return 0;
    if (p[1] != 'O') return 1;
    if (p[2] != 'C') return 2;
    if (p[3] != '!') return 3;
    __builtin_trap();
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
