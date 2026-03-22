use inkwell::context::Context;
use inkwell::module::{Module, Linkage};

pub fn inject_preamble<'a>(ctx: &'a Context, module: &Module<'a>, bpf_hooks: Vec<(String, Vec<u8>)>) {
    let void_type = ctx.void_type();
    let i8_type = ctx.i8_type();
    let i32_type = ctx.i32_type();
    let i64_type = ctx.i64_type();
    let i8_ptr_type = i8_type.ptr_type(inkwell::AddressSpace::default());

    let bootstrap_fn = module.add_function("telos_bootstrap", void_type.fn_type(&[], false), Some(Linkage::Internal));
    let basic_block = ctx.append_basic_block(bootstrap_fn, "entry");
    let builder = ctx.create_builder();
    builder.position_at_end(basic_block);

    // Common license
    let license_arr = i8_type.const_array(&[
        i8_type.const_int('G' as u64, false),
        i8_type.const_int('P' as u64, false),
        i8_type.const_int('L' as u64, false),
        i8_type.const_int(0, false),
    ]);
    let global_license = module.add_global(license_arr.get_type(), None, "__telos_bpf_license");
    global_license.set_initializer(&license_arr);

    let asm_fn_type = i32_type.fn_type(&[i64_type.into(), i64_type.into(), i64_type.into(), i64_type.into()], false);
    let bpf_syscall_asm = ctx.create_inline_asm(
        asm_fn_type,
        "syscall".to_string(),
        "={rax},{rax},{rdi},{rsi},{rdx},~{rcx},~{r11},~{memory}".to_string(),
        true, false, None, false
    );

    let abort_asm_fn_type = i32_type.fn_type(&[i64_type.into(), i64_type.into()], false);
    let abort_syscall_asm = ctx.create_inline_asm(
        abort_asm_fn_type,
        "syscall".to_string(),
        "={rax},{rax},{rdi},~{rcx},~{r11},~{memory}".to_string(),
        true, false, None, false
    );

    for (id, (_name, bytes)) in bpf_hooks.iter().enumerate() {
        let bpf_array = i8_type.const_array(&bytes.iter().map(|&b| i8_type.const_int(b as u64, false)).collect::<Vec<_>>());
        let global_bpf = module.add_global(bpf_array.get_type(), None, &format!("__telos_bpf_bytecode_{}", id));
        global_bpf.set_initializer(&bpf_array);
        global_bpf.set_section(Some(".telos_sandbox"));
        
        let attr_array_type = i8_type.array_type(144);
        let attr_alloca = builder.build_alloca(attr_array_type, &format!("bpf_attr_{}", id));
        builder.build_store(attr_alloca, attr_array_type.const_zero()); // zero-init
        let i8_ptr = builder.build_pointer_cast(attr_alloca, i8_ptr_type, "attr_i8_ptr");

        // prog_type = 29
        let prog_type_ptr = builder.build_pointer_cast(i8_ptr, i32_type.ptr_type(inkwell::AddressSpace::default()), "prog_type_ptr");
        builder.build_store(prog_type_ptr, i32_type.const_int(29, false));

        // insn_cnt = bytes.len() / 8
        let insn_cnt_gep = unsafe { builder.build_gep(i8_type, i8_ptr, &[i32_type.const_int(4, false)], "") };
        let insn_cnt_ptr = builder.build_pointer_cast(insn_cnt_gep, i32_type.ptr_type(inkwell::AddressSpace::default()), "");
        builder.build_store(insn_cnt_ptr, i32_type.const_int((bytes.len()/8) as u64, false));

        // insns
        let insns_gep = unsafe { builder.build_gep(i8_type, i8_ptr, &[i32_type.const_int(8, false)], "") };
        let insns_ptr = builder.build_pointer_cast(insns_gep, i64_type.ptr_type(inkwell::AddressSpace::default()), "");
        builder.build_store(insns_ptr, builder.build_ptr_to_int(global_bpf.as_pointer_value(), i64_type, ""));

        // license
        let license_gep = unsafe { builder.build_gep(i8_type, i8_ptr, &[i32_type.const_int(16, false)], "") };
        let license_ptr = builder.build_pointer_cast(license_gep, i64_type.ptr_type(inkwell::AddressSpace::default()), "");
        builder.build_store(license_ptr, builder.build_ptr_to_int(global_license.as_pointer_value(), i64_type, ""));

        // expected_attach_type (BPF_LSM_MAC = 27)
        let attach_gep = unsafe { builder.build_gep(i8_type, i8_ptr, &[i32_type.const_int(68, false)], "") };
        let attach_ptr = builder.build_pointer_cast(attach_gep, i32_type.ptr_type(inkwell::AddressSpace::default()), "");
        builder.build_store(attach_ptr, i32_type.const_int(27, false));

        // Call BPF_PROG_LOAD (5)
        let load_res = builder.build_indirect_call(
            asm_fn_type, bpf_syscall_asm,
            &[
                i64_type.const_int(321, false).into(), 
                i64_type.const_int(5, false).into(), 
                builder.build_ptr_to_int(attr_alloca, i64_type, "").into(), 
                i64_type.const_int(144, false).into()
            ],
            "sys_bpf_load"
        ).try_as_basic_value().left().unwrap().into_int_value();

        // Check if load_res < 0
        let zero = i32_type.const_int(0, false);
        let is_err = builder.build_int_compare(inkwell::IntPredicate::SLT, load_res, zero, "is_err");
        let abort_bb = ctx.append_basic_block(bootstrap_fn, &format!("abort_bb_{}", id));
        let cont_bb = ctx.append_basic_block(bootstrap_fn, &format!("cont_bb_{}", id));
        builder.build_conditional_branch(is_err, abort_bb, cont_bb);

        builder.position_at_end(abort_bb);
        builder.build_indirect_call(abort_asm_fn_type, abort_syscall_asm, &[i64_type.const_int(60, false).into(), i64_type.const_int(1, false).into()], "sys_exit");
        builder.build_unreachable();

        builder.position_at_end(cont_bb);

        // Call BPF_PROG_ATTACH (8)
        let attr_array_type_16 = i8_type.array_type(16);
        let attr_alloca_attach = builder.build_alloca(attr_array_type_16, &format!("bpf_attr_attach_{}", id));
        builder.build_store(attr_alloca_attach, attr_array_type_16.const_zero());
        let i8_ptr_attach = builder.build_pointer_cast(attr_alloca_attach, i8_ptr_type, "");

        // attach_bpf_fd at offset 4 (load_res)
        let attach_fd_gep = unsafe { builder.build_gep(i8_type, i8_ptr_attach, &[i32_type.const_int(4, false)], "") };
        builder.build_store(builder.build_pointer_cast(attach_fd_gep, i32_type.ptr_type(inkwell::AddressSpace::default()), ""), load_res);

        // attach_type at offset 8 (27 = BPF_LSM_MAC)
        let attach_type_gep = unsafe { builder.build_gep(i8_type, i8_ptr_attach, &[i32_type.const_int(8, false)], "") };
        builder.build_store(builder.build_pointer_cast(attach_type_gep, i32_type.ptr_type(inkwell::AddressSpace::default()), ""), i32_type.const_int(27, false));

        let attach_res = builder.build_indirect_call(
            asm_fn_type, bpf_syscall_asm,
            &[
                i64_type.const_int(321, false).into(), 
                i64_type.const_int(8, false).into(), 
                builder.build_ptr_to_int(attr_alloca_attach, i64_type, "").into(), 
                i64_type.const_int(16, false).into()
            ],
            "sys_bpf_attach"
        ).try_as_basic_value().left().unwrap().into_int_value();

        // Check if attach_res < 0
        let is_err_attach = builder.build_int_compare(inkwell::IntPredicate::SLT, attach_res, zero, "is_err_attach");
        let abort_bb_attach = ctx.append_basic_block(bootstrap_fn, &format!("abort_bb_attach_{}", id));
        let cont_bb_attach = ctx.append_basic_block(bootstrap_fn, &format!("cont_bb_attach_{}", id));
        builder.build_conditional_branch(is_err_attach, abort_bb_attach, cont_bb_attach);

        builder.position_at_end(abort_bb_attach);
        builder.build_indirect_call(abort_asm_fn_type, abort_syscall_asm, &[i64_type.const_int(60, false).into(), i64_type.const_int(1, false).into()], "sys_exit");
        builder.build_unreachable();

        builder.position_at_end(cont_bb_attach);
    }
    
    builder.build_return(None);

    // Append to llvm.global_ctors
    let ctor_struct_type = ctx.struct_type(&[
        i32_type.into(), 
        bootstrap_fn.as_global_value().as_pointer_value().get_type().into(), 
        i8_ptr_type.into()
    ], false);
    
    let ctor_struct_val = ctor_struct_type.const_named_struct(&[
        i32_type.const_int(65535, false).into(),
        bootstrap_fn.as_global_value().as_pointer_value().into(),
        i8_ptr_type.const_null().into()
    ]);
    
    let ctor_array = ctor_struct_type.const_array(&[ctor_struct_val]);
    let global_ctors = module.add_global(ctor_array.get_type(), None, "llvm.global_ctors");
    global_ctors.set_linkage(inkwell::module::Linkage::Appending);
    global_ctors.set_initializer(&ctor_array);
}
