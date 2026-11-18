/* Before readiness every OEM entry is an ABI-transparent tail gateway. No GNU
 * object, cleanup, or exception frame remains when the original is entered. */
.text
.macro VBC_GATE name, number
.p2align 2
.global \name
.type \name,@function
\name:
.cfi_startproc
    sub sp, sp, #208
.cfi_def_cfa_offset 208
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x30, [sp, #64]
.cfi_offset x30, -136
    stp q0, q1, [sp, #80]
    stp q2, q3, [sp, #112]
    stp q4, q5, [sp, #144]
    stp q6, q7, [sp, #176]
    mov w0, #\number
    bl vbc_i18n_gateway_target
    mov x16, x0
    ldp q0, q1, [sp, #80]
    ldp q2, q3, [sp, #112]
    ldp q4, q5, [sp, #144]
    ldp q6, q7, [sp, #176]
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x30, [sp, #64]
.cfi_restore x30
    add sp, sp, #208
.cfi_def_cfa_offset 0
    cbz x16, 1f
    br x16
1:  b abort
.cfi_endproc
.size \name, .-\name
.endm
/* Application::main name is added only after actual A9/A11 symbol receipt. */
VBC_GATE _ZN5kanzi15ResourceManager20addDirectoryFromFileEN5boost17basic_string_viewIcSt11char_traitsIcEEE,1
VBC_GATE _ZN5kanzi8Resource6setKZBEPK18KzuBinaryDirectoryN5boost17basic_string_viewIcSt11char_traitsIcEEE,2
VBC_GATE _ZN5kanzi15ResourceManager15removeDirectoryEP18KzuBinaryDirectory,3
VBC_GATE _ZN5kanzi18ResourceDictionary3addERKNS_10ResourceIDEN5boost17basic_string_viewIcSt11char_traitsIcEEE,4
VBC_GATE _ZN5kanzi18ResourceDictionaryD1Ev,5
VBC_GATE _ZN5kanzi15ResourceManager10addKzbFileEN5boost17basic_string_viewIcSt11char_traitsIcEEE,6
VBC_GATE _ZN5kanzi7KzbFileC1EPNS_6DomainESt10unique_ptrINS_4FileESt14default_deleteIS4_EE,7
VBC_GATE _ZN5kanzi18ResourceDictionary11loadFromKZBEPNS_6DomainEN5boost17basic_string_viewIcSt11char_traitsIcEEERNS_7KzbFileERNS_18ReadOnlyMemoryFileERNS_15KzbMemoryParserE,8
VBC_GATE _ZN5kanzi8Resource6setUrlEN5boost17basic_string_viewIcSt11char_traitsIcEEE,9
VBC_GATE _ZN5kanzi15ResourceManager13removeKzbFileEN5boost17basic_string_viewIcSt11char_traitsIcEEE,10
.section .note.GNU-stack,"",@progbits
