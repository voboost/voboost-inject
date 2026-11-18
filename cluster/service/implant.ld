/* QNX loader-compatible two-LOAD layout; mutable data remains outside RELRO. */
PHDRS {
 phdr PT_PHDR PHDRS;
 text PT_LOAD FILEHDR PHDRS FLAGS(5);
 data PT_LOAD FLAGS(6);
 dynamic PT_DYNAMIC FLAGS(6);
 relro PT_GNU_RELRO FLAGS(4);
 stack PT_GNU_STACK FLAGS(6);
 note PT_NOTE FLAGS(4);
}
SECTIONS {
 . = SIZEOF_HEADERS;
 .note.gnu.build-id : { *(.note.gnu.build-id) } :text :note
 .dynsym : { *(.dynsym) } :text
 .gnu.hash : { *(.gnu.hash) } :text
 .hash : { *(.hash) } :text
 .dynstr : { *(.dynstr) } :text
 .rela.dyn : { *(.rela.dyn) } :text
 .rela.plt : { *(.rela.plt) } :text
 .rodata : { *(.rodata .rodata.*) } :text
 .eh_frame : { *(.eh_frame) } :text
 .text : { *(.text .text.*) } :text
 .plt : { *(.plt) } :text
 . = ALIGN(0x10000);
 .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) } :data :relro
 .init_array : { KEEP(*(.init_array .init_array.*)) } :data :relro
 .dynamic : { *(.dynamic) } :data :dynamic :relro
 .got : { *(.got) } :data :relro
 .got.plt : { *(.got.plt) } :data :relro
 .relro_padding : { . = ALIGN(4096); } :data :relro
 .data : { *(.data .data.*) } :data
 .bss : { *(.bss .bss.* COMMON) } :data
 .comment 0 : { *(.comment) }
 /DISCARD/ : { *(.note.GNU-stack) }
}
