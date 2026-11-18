/* OEM CRT argument layout and the complete guest29 linker recipe are retained. */
.text
.p2align 2
.global _start
.type _start,%function
_start:
    mov x4,x0
    ldr w0,[sp]
    add x1,sp,#8
    add x2,x1,x0,lsl#3
    add x2,x2,#8
    mov x3,x2
1:
    ldr x5,[x3],#8
    cbnz x5,1b
    mov x19,x0
    mov x20,x1
    mov x21,x2
    bl _init_libc
    mov x0,x19
    mov x1,x20
    mov x2,x21
    bl main
    bl exit
    brk #0
.size _start,.-_start
.section .note.qnx,"a",@note
.p2align 2
.long 4,8,3
.asciz "QNX"
.long 0,4096
