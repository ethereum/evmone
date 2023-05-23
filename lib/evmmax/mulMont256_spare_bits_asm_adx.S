	.text
	.intel_syntax noprefix
	.file	"@mlimbs_asm_mul_mont_x86_adx_bmi2.nim.c"
	.hidden	mulMont_CIOS_sparebit_asm_adx__limbs95asm95mul95mont95x565495adx95bmi50_424 # -- Begin function mulMont_CIOS_sparebit_asm_adx__limbs95asm95mul95mont95x565495adx95bmi50_424
	.globl	mulMont_CIOS_sparebit_asm_adx__limbs95asm95mul95mont95x565495adx95bmi50_424
	.p2align	4, 0x90
	.type	mulMont_CIOS_sparebit_asm_adx__limbs95asm95mul95mont95x565495adx95bmi50_424,@function
mulMont_CIOS_sparebit_asm_adx__limbs95asm95mul95mont95x565495adx95bmi50_424: # @mulMont_CIOS_sparebit_asm_adx__limbs95asm95mul95mont95x565495adx95bmi50_424
	.cfi_startproc
# %bb.0:
	push	r15
	.cfi_def_cfa_offset 16
	push	r14
	.cfi_def_cfa_offset 24
	push	r12
	.cfi_def_cfa_offset 32
	push	rbx
	.cfi_def_cfa_offset 40
	.cfi_offset rbx, -40
	.cfi_offset r12, -32
	.cfi_offset r14, -24
	.cfi_offset r15, -16
	mov	r9, rdx
	#APP

	#   Outer loop i = 0
	mov	rdx, qword ptr [r9]
	mulx	rbx, r11, qword ptr [rsi]
	xor	r12, r12
	mulx	rax, r15, qword ptr [rsi + 8]
	add	rbx, r15
	mulx	r14, r15, qword ptr [rsi + 16]
	adc	rax, r15
	#   Outer loop i = 0, last limb
	mulx	r12, r15, qword ptr [rsi + 24]
	adc	r14, r15
	#   Accumulate last carries in hi word
	adc	r12, 0
	#   Reduction
	#   m = t[0] * m0ninv mod 2^w
	mov	rdx, r11
	imul	rdx, r8
	xor	r15, r15
	#   S,_ := t[0] + m*M[0]
	mulx	r15, r10, qword ptr [rcx]
	adcx	r10, r11
	mov	r11, r15
	mov	r10, 0
	#   for j=1 to N-1
	#     (S,t[j-1]) := t[j] + m*M[j] + S
	adcx	r11, rbx
	mulx	rbx, r15, qword ptr [rcx + 8]
	adox	r11, r15
	adcx	rbx, rax
	mulx	rax, r15, qword ptr [rcx + 16]
	adox	rbx, r15
	adcx	rax, r14
	mulx	r14, r15, qword ptr [rcx + 24]
	adox	rax, r15
	#   Reduction carry 
	adcx	r10, r12
	adox	r14, r10
	#   Outer loop i = 1, j in [0, 4)
	mov	rdx, qword ptr [r9 + 8]
	xor	r12, r12
	mulx	r12, r15, qword ptr [rsi]
	adox	r11, r15
	adcx	rbx, r12
	mulx	r12, r15, qword ptr [rsi + 8]
	adox	rbx, r15
	adcx	rax, r12
	mulx	r12, r15, qword ptr [rsi + 16]
	adox	rax, r15
	adcx	r14, r12
	#   Outer loop i = 1, last limb
	mulx	r12, r15, qword ptr [rsi + 24]
	adox	r14, r15
	#   Accumulate last carries in hi word
	mov	rdx, 0
	adcx	r12, rdx
	adox	r12, rdx
	#   Reduction
	#   m = t[0] * m0ninv mod 2^w
	mov	rdx, r11
	imul	rdx, r8
	xor	r15, r15
	#   S,_ := t[0] + m*M[0]
	mulx	r15, r10, qword ptr [rcx]
	adcx	r10, r11
	mov	r11, r15
	mov	r10, 0
	#   for j=1 to N-1
	#     (S,t[j-1]) := t[j] + m*M[j] + S
	adcx	r11, rbx
	mulx	rbx, r15, qword ptr [rcx + 8]
	adox	r11, r15
	adcx	rbx, rax
	mulx	rax, r15, qword ptr [rcx + 16]
	adox	rbx, r15
	adcx	rax, r14
	mulx	r14, r15, qword ptr [rcx + 24]
	adox	rax, r15
	#   Reduction carry 
	adcx	r10, r12
	adox	r14, r10
	#   Outer loop i = 2, j in [0, 4)
	mov	rdx, qword ptr [r9 + 16]
	xor	r12, r12
	mulx	r12, r15, qword ptr [rsi]
	adox	r11, r15
	adcx	rbx, r12
	mulx	r12, r15, qword ptr [rsi + 8]
	adox	rbx, r15
	adcx	rax, r12
	mulx	r12, r15, qword ptr [rsi + 16]
	adox	rax, r15
	adcx	r14, r12
	#   Outer loop i = 2, last limb
	mulx	r12, r15, qword ptr [rsi + 24]
	adox	r14, r15
	#   Accumulate last carries in hi word
	mov	rdx, 0
	adcx	r12, rdx
	adox	r12, rdx
	#   Reduction
	#   m = t[0] * m0ninv mod 2^w
	mov	rdx, r11
	imul	rdx, r8
	xor	r15, r15
	#   S,_ := t[0] + m*M[0]
	mulx	r15, r10, qword ptr [rcx]
	adcx	r10, r11
	mov	r11, r15
	mov	r10, 0
	#   for j=1 to N-1
	#     (S,t[j-1]) := t[j] + m*M[j] + S
	adcx	r11, rbx
	mulx	rbx, r15, qword ptr [rcx + 8]
	adox	r11, r15
	adcx	rbx, rax
	mulx	rax, r15, qword ptr [rcx + 16]
	adox	rbx, r15
	adcx	rax, r14
	mulx	r14, r15, qword ptr [rcx + 24]
	adox	rax, r15
	#   Reduction carry 
	adcx	r10, r12
	adox	r14, r10
	#   Outer loop i = 3, j in [0, 4)
	mov	rdx, qword ptr [r9 + 24]
	xor	r12, r12
	mulx	r12, r15, qword ptr [rsi]
	adox	r11, r15
	adcx	rbx, r12
	mulx	r12, r15, qword ptr [rsi + 8]
	adox	rbx, r15
	adcx	rax, r12
	mulx	r12, r15, qword ptr [rsi + 16]
	adox	rax, r15
	adcx	r14, r12
	#   Outer loop i = 3, last limb
	mulx	r12, r15, qword ptr [rsi + 24]
	adox	r14, r15
	#   Accumulate last carries in hi word
	mov	rdx, 0
	adcx	r12, rdx
	adox	r12, rdx
	#   Reduction
	#   m = t[0] * m0ninv mod 2^w
	mov	rdx, r11
	imul	rdx, r8
	xor	r15, r15
	#   S,_ := t[0] + m*M[0]
	mulx	r15, r10, qword ptr [rcx]
	adcx	r10, r11
	mov	r11, r15
	mov	r10, 0
	#   for j=1 to N-1
	#     (S,t[j-1]) := t[j] + m*M[j] + S
	adcx	r11, rbx
	mulx	rbx, r15, qword ptr [rcx + 8]
	adox	r11, r15
	adcx	rbx, rax
	mulx	rax, r15, qword ptr [rcx + 16]
	adox	rbx, r15
	adcx	rax, r14
	mulx	r14, r15, qword ptr [rcx + 24]
	adox	rax, r15
	#   Reduction carry 
	adcx	r10, r12
	adox	r14, r10
	# Final substraction (cannot overflow its limbs)
	mov	rsi, r11
	sub	rsi, qword ptr [rcx]
	mov	r9, rbx
	sbb	r9, qword ptr [rcx + 8]
	mov	r12, rax
	sbb	r12, qword ptr [rcx + 16]
	mov	r15, r14
	sbb	r15, qword ptr [rcx + 24]
	cmovae	r11, rsi
	mov	qword ptr [rdi], r11
	cmovae	rbx, r9
	mov	qword ptr [rdi + 8], rbx
	cmovae	rax, r12
	mov	qword ptr [rdi + 16], rax
	cmovae	r14, r15
	mov	qword ptr [rdi + 24], r14


	#NO_APP
	pop	rbx
	.cfi_def_cfa_offset 32
	pop	r12
	.cfi_def_cfa_offset 24
	pop	r14
	.cfi_def_cfa_offset 16
	pop	r15
	.cfi_def_cfa_offset 8
	ret
.Lfunc_end0:
	.size	mulMont_CIOS_sparebit_asm_adx__limbs95asm95mul95mont95x565495adx95bmi50_424, .Lfunc_end0-mulMont_CIOS_sparebit_asm_adx__limbs95asm95mul95mont95x565495adx95bmi50_424
	.cfi_endproc
                                        # -- End function
