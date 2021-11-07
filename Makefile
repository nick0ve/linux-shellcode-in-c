.PHONY: all clean copy

CC=gcc
OBJCOPY=objcopy

all: implant.bin

clean:
	$(RM) *.bin *.elf

implant.bin: implant.elf
	$(OBJCOPY) -O binary $< $@

implant.elf: scode.c scode.ld
	$(CC) -nostdlib -nodefaultlibs -nostdinc -T scode.ld -fpic -fno-stack-protector -fcf-protection=none\
		-Os -std=gnu11 -Wall -Wextra -o $@ $<
