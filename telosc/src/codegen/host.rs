use std::path::Path;
use inkwell::context::Context;
use inkwell::targets::{TargetMachine, FileType};
use crate::parser::Function;
use crate::codegen::bootstrap;

pub fn emit_executable<'a>(ctx: &'a Context, machine: &TargetMachine, _functions: &[Function], bpf_hooks: Vec<(String, Vec<u8>)>) {
    let module = ctx.create_module("telos_host");
    
    // Inject the fail-closed bootstrap routine (currently just embedding)
    bootstrap::inject_preamble(ctx, &module, bpf_hooks);
    
    // Add dummy main function to make it a valid executable
    let i32_type = ctx.i32_type();
    let main_fn_type = i32_type.fn_type(&[], false);
    let main_fn = module.add_function("main", main_fn_type, None);
    let builder = ctx.create_builder();
    let basic_block = ctx.append_basic_block(main_fn, "entry");
    builder.position_at_end(basic_block);
    let i64_type = ctx.i64_type();
    let i16_type = ctx.i16_type();

    let asm_fn_type = i32_type.fn_type(&[i64_type.into(), i64_type.into(), i64_type.into()], false);

    // socket(AF_INET, SOCK_STREAM, 0)
    let socket_call = ctx.create_inline_asm(
        asm_fn_type,
        "syscall".to_string(),
        "={rax},{rax},{rdi},{rsi},{rdx},~{rcx},~{r11},~{memory}".to_string(),
        true, false, None, false
    );
    
    let sock_res = builder.build_indirect_call(
        asm_fn_type, socket_call,
        &[i64_type.const_int(41, false).into(), i64_type.const_int(2, false).into(), i64_type.const_int(1, false).into()],
        "sys_socket"
    ).try_as_basic_value().left().unwrap().into_int_value();

    let sock_fd = builder.build_int_cast(sock_res, i64_type, "sock_fd");

    // sockaddr_in setup (16 bytes)
    let sockaddr_type = ctx.struct_type(&[i16_type.into(), i16_type.into(), i32_type.into(), i64_type.into()], false);
    let sockaddr_alloca = builder.build_alloca(sockaddr_type, "sockaddr");
    let sockaddr_val = sockaddr_type.const_named_struct(&[
        i16_type.const_int(2, false).into(),          // AF_INET
        i16_type.const_int(0x5000, false).into(),     // Port 80
        i32_type.const_int(0x22D8B85D, false).into(), // 93.184.216.34
        i64_type.const_int(0, false).into()           // padding
    ]);
    builder.build_store(sockaddr_alloca, sockaddr_val);

    // connect(fd, &addr, 16)
    let connect_call = ctx.create_inline_asm(
        asm_fn_type,
        "syscall".to_string(),
        "={rax},{rax},{rdi},{rsi},{rdx},~{rcx},~{r11},~{memory}".to_string(),
        true, false, None, false
    );
    
    let connect_res = builder.build_indirect_call(
        asm_fn_type, connect_call,
        &[i64_type.const_int(42, false).into(), sock_fd.into(), builder.build_ptr_to_int(sockaddr_alloca, i64_type, "").into(), i64_type.const_int(16, false).into()],
        "sys_connect"
    ).try_as_basic_value().left().unwrap().into_int_value();

    // Check result
    let zero = i32_type.const_int(0, false);
    let is_err = builder.build_int_compare(inkwell::IntPredicate::SLT, connect_res, zero, "is_err");
    let fail_bb = ctx.append_basic_block(main_fn, "fail_bb");
    let succ_bb = ctx.append_basic_block(main_fn, "succ_bb");
    builder.build_conditional_branch(is_err, fail_bb, succ_bb);
    
    builder.position_at_end(fail_bb);
    builder.build_return(Some(&connect_res));

    builder.position_at_end(succ_bb);
    builder.build_return(Some(&zero));

    // Machine emit to object
    machine.write_to_file(&module, FileType::Object, Path::new("output.o")).unwrap();
}
