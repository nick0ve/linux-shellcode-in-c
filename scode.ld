ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x400000, LENGTH = 0x4000
}

SECTIONS
{
    .text :
    {
        *(.text.start)
        *(.text*)
    }

    .data :
    {
        *(.data*)
    }

    .bss :
    {
        _bss = .;
        *(.bss*)
        *(COMMON)
        _ebss = .;
    }

    .rodata :
    {
        *(.rodata*)
    }
}
