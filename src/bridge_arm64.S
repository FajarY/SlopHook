/*
 * Register-context bridge for instrumentation hooks.
 *
 * Reached from a per-hook closure (built by hook.c) which has already done:
 *      sub sp, sp, #16
 *      str x17, [sp, #8]        // the real X17, which we must not lose
 *      <load &closure_info>     // into x17
 *      str x17, [sp, #0]
 *      br  <this>
 *
 * So on entry:  [sp + 0] = &sh_closure_info
 *               [sp + 8] = caller's X17
 *
 * sh_context layout - must match include/slophook.h exactly:
 *      0   x0..x30   (31 * 8 = 248 bytes)
 *      248 sp
 *      256 pc
 *      264 nzcv
 *      272 q0..q7   (8 * 16 = 128 bytes)
 *      400 total
 *
 * sh_closure_info layout - must match src/hook.c:
 *      0 cb   8 user   16 resume   24 pc
 */
/*
 * Mirror whatever branch-protection the C translation units were built with.
 * Without this note the linker finds one unmarked input object and drops the
 * GNU property from the whole shared library, silently disabling BTI (and
 * PAC-ret marking) for everything in it.
 */
#if defined(__ARM_FEATURE_BTI_DEFAULT) || defined(__ARM_FEATURE_PAC_DEFAULT)
# if defined(__ARM_FEATURE_BTI_DEFAULT)
#  define SH_BTI 1
# else
#  define SH_BTI 0
# endif
# if defined(__ARM_FEATURE_PAC_DEFAULT)
#  define SH_PAC 2
# else
#  define SH_PAC 0
# endif
    .section .note.gnu.property, "a", %note
    .balign 8
    .long 4                      /* n_namesz */
    .long 16                     /* n_descsz */
    .long 5                      /* NT_GNU_PROPERTY_TYPE_0 */
    .asciz "GNU"
    .long 0xc0000000             /* GNU_PROPERTY_AARCH64_FEATURE_1_AND */
    .long 4
    .long (SH_BTI | SH_PAC)
    .long 0
#endif

    .text
    .balign 4
    .global sh_bridge_entry
    .type   sh_bridge_entry, %function
sh_bridge_entry:
#if defined(__ARM_FEATURE_BTI_DEFAULT)
    /* the per-hook closure arrives here via BR X17, so this needs a
     * landing pad once the page is mapped PROT_BTI */
    hint    #34                  /* bti c */
#endif
    sub     sp, sp, #400

    stp     x0,  x1,  [sp, #0]
    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]      /* x17 slot is wrong; corrected below */
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30,      [sp, #240]

    ldr     x9,  [sp, #408]           /* caller's real X17 */
    str     x9,  [sp, #136]           /* -> ctx.x[17] */
    add     x9,  sp,  #416            /* SP as it was at the hooked insn */
    str     x9,  [sp, #248]

    ldr     x19, [sp, #400]           /* &closure_info (x19 survives the call) */
    ldr     x9,  [x19, #24]           /* info->pc */
    str     x9,  [sp, #256]
    mrs     x9,  nzcv
    str     x9,  [sp, #264]

    stp     q0,  q1,  [sp, #272]
    stp     q2,  q3,  [sp, #304]
    stp     q4,  q5,  [sp, #336]
    stp     q6,  q7,  [sp, #368]

    mov     x0,  sp                   /* sh_context *ctx */
    ldr     x1,  [x19, #8]            /* void *user         */
    ldr     x2,  [x19, #0]            /* sh_instrument_cb   */
    blr     x2

    /* Hand the resume address, and X17 as the callback left it, to the
     * two-instruction stub that fronts the relocated prologue. */
    ldr     x9,  [x19, #16]           /* info->resume */
    str     x9,  [sp, #400]
    ldr     x9,  [sp, #136]           /* ctx.x[17], possibly modified */
    str     x9,  [sp, #408]

    ldp     q0,  q1,  [sp, #272]
    ldp     q2,  q3,  [sp, #304]
    ldp     q4,  q5,  [sp, #336]
    ldp     q6,  q7,  [sp, #368]
    ldr     x9,  [sp, #264]
    msr     nzcv, x9

    ldp     x0,  x1,  [sp, #0]
    ldp     x2,  x3,  [sp, #16]
    ldp     x4,  x5,  [sp, #32]
    ldp     x6,  x7,  [sp, #48]
    ldp     x8,  x9,  [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30,      [sp, #240]

    add     sp,  sp,  #400            /* sp is back at the closure's block */
    ldr     x17, [sp, #0]             /* resume stub address               */
    br      x17                       /* the stub reloads X17 from [sp,#8] */

    .size sh_bridge_entry, . - sh_bridge_entry
    .section .note.GNU-stack,"",%progbits
