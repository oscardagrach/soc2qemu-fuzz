MEMORY { FLASH (rx) : ORIGIN = 0x0, LENGTH = 4M  RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 4M }
SECTIONS {
  .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) } > FLASH
  .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
  _stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
