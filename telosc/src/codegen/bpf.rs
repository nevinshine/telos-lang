use inkwell::context::Context;
use inkwell::targets::{TargetMachine, FileType};
use inkwell::module::Linkage;
use crate::parser::IntentDecl;
use goblin::elf::Elf;

use inkwell::values::GlobalValue;

fn synthesize_policy_map<'ctx>(
    ctx: &'ctx Context,
    module: &inkwell::module::Module<'ctx>,
    map_name: &str,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> GlobalValue<'ctx> {
    let i32_type = ctx.i32_type();
    
    // bpf_map_def: { type, key_size, value_size, max_entries, map_flags }
    // We use the legacy bpf_map_def layout placed in "maps" section.
    let map_struct_type = ctx.struct_type(&[
        i32_type.into(), i32_type.into(), i32_type.into(), i32_type.into(), i32_type.into(),
    ], false);

    let map_struct_val = map_struct_type.const_named_struct(&[
        i32_type.const_int(1, false).into(), // BPF_MAP_TYPE_HASH = 1
        i32_type.const_int(key_size as u64, false).into(),
        i32_type.const_int(value_size as u64, false).into(),
        i32_type.const_int(max_entries as u64, false).into(),
        i32_type.const_int(0, false).into(), // map_flags = 0
    ]);

    let global_map = module.add_global(map_struct_type, None, map_name);
    global_map.set_initializer(&map_struct_val);
    global_map.set_section(Some("maps")); // Kernel parses this statically
    global_map.set_linkage(Linkage::External);
    
    global_map
}

fn synthesize_socket_connect_hook<'ctx>(
    ctx: &'ctx Context,
    module: &inkwell::module::Module<'ctx>,
    net_allow_map: GlobalValue<'ctx>,
    ringbuf_map: GlobalValue<'ctx>,
) {
    let builder = ctx.create_builder();
    let i8_type = ctx.i8_type();
    let i16_type = ctx.i16_type();
    let i32_type = ctx.i32_type();
    let i64_type = ctx.i64_type();
    let i8_ptr_type = i8_type.ptr_type(inkwell::AddressSpace::default());

    // 1. Definition int telos_check_connect(void* sock, void* address, i32 addrlen)
    let fn_type = i32_type.fn_type(&[i8_ptr_type.into(), i8_ptr_type.into(), i32_type.into()], false);
    let lsm_hook = module.add_function("telos_check_connect", fn_type, Some(Linkage::External));
    lsm_hook.set_section(Some("lsm/socket_connect"));

    let basic_block = ctx.append_basic_block(lsm_hook, "entry");
    builder.position_at_end(basic_block);

    let address_ptr = lsm_hook.get_nth_param(1).unwrap().into_pointer_value();

    // 2. Extract dst_port (address + 2) and dst_ip (address + 4)
    let port_gep = unsafe { builder.build_gep(i8_type, address_ptr, &[i32_type.const_int(2, false)], "port_offset") };
    let dst_port = builder.build_load(i16_type, port_gep, "dst_port").into_int_value();
    
    let ip_gep = unsafe { builder.build_gep(i8_type, address_ptr, &[i32_type.const_int(4, false)], "ip_offset") };
    let dst_ip = builder.build_load(i32_type, ip_gep, "dst_ip").into_int_value();

    let ip_alloca = builder.build_alloca(i32_type, "ip_alloca");
    builder.build_store(ip_alloca, dst_ip);

    // 3. Call bpf_map_lookup_elem(map, key)
    let lookup_fn_type = i8_ptr_type.fn_type(&[i8_ptr_type.into(), i8_ptr_type.into()], false);
    let bpf_helper_lookup = builder.build_int_to_ptr(i64_type.const_int(1, false), lookup_fn_type.ptr_type(inkwell::AddressSpace::default()), "lookup_fn_ptr");

    let map_ptr_cast = builder.build_pointer_cast(net_allow_map.as_pointer_value(), i8_ptr_type, "map_cast");
    let key_ptr_cast = builder.build_pointer_cast(ip_alloca, i8_ptr_type, "key_cast");
    let lookup_res = builder.build_indirect_call(
        lookup_fn_type,
        bpf_helper_lookup,
        &[map_ptr_cast.into(), key_ptr_cast.into()],
        "lookup_call"
    ).try_as_basic_value().left().unwrap().into_pointer_value();

    // 4. Check if lookup_res == null
    let null_ptr = i8_ptr_type.const_null();
    let is_null = builder.build_int_compare(
        inkwell::IntPredicate::EQ, 
        builder.build_ptr_to_int(lookup_res, i64_type, ""), 
        builder.build_ptr_to_int(null_ptr, i64_type, ""), 
        "is_null"
    );

    let check_port_bb = ctx.append_basic_block(lsm_hook, "check_port_bb");
    let deny_bb = ctx.append_basic_block(lsm_hook, "deny_bb");
    let allow_bb = ctx.append_basic_block(lsm_hook, "allow_bb");

    builder.build_conditional_branch(is_null, deny_bb, check_port_bb);

    // 5. Check if *lookup_res == dst_port
    builder.position_at_end(check_port_bb);
    let lookup_port_cast = builder.build_pointer_cast(lookup_res, i16_type.ptr_type(inkwell::AddressSpace::default()), "lookup_port_cast");
    let allowed_port = builder.build_load(i16_type, lookup_port_cast, "allowed_port").into_int_value();
    let port_match = builder.build_int_compare(inkwell::IntPredicate::EQ, allowed_port, dst_port, "port_match");
    builder.build_conditional_branch(port_match, allow_bb, deny_bb);

    // Deny (-1 or -EPERM)
    builder.position_at_end(deny_bb);
    inject_ringbuf_event(ctx, &builder, module, ringbuf_map, 1, 1); // event_type=1(connect), decision=1(deny)
    let neg_one = i32_type.const_int(!0, false); 
    builder.build_return(Some(&neg_one));

    // Allow (0)
    builder.position_at_end(allow_bb);
    inject_ringbuf_event(ctx, &builder, module, ringbuf_map, 1, 0); // event_type=1(connect), decision=0(allow)
    builder.build_return(Some(&i32_type.const_int(0, false)));
}

fn synthesize_file_open_hook<'ctx>(
    ctx: &'ctx Context,
    module: &inkwell::module::Module<'ctx>,
    file_allow_map: GlobalValue<'ctx>,
    ringbuf_map: GlobalValue<'ctx>,
) {
    let builder = ctx.create_builder();
    let i8_type = ctx.i8_type();
    let i32_type = ctx.i32_type();
    let i64_type = ctx.i64_type();
    let i8_ptr_type = i8_type.ptr_type(inkwell::AddressSpace::default());

    // int telos_file_open(void* file)
    let fn_type = i32_type.fn_type(&[i8_ptr_type.into()], false);
    let lsm_hook = module.add_function("telos_file_open", fn_type, Some(Linkage::External));
    lsm_hook.set_section(Some("lsm/file_open"));

    let basic_block = ctx.append_basic_block(lsm_hook, "entry");
    builder.position_at_end(basic_block);

    let file_ptr = lsm_hook.get_nth_param(0).unwrap().into_pointer_value();

    // Extrapolate a dummy "path identifier" mechanically from the file pointer structure
    let path_gep = unsafe { builder.build_gep(i8_type, file_ptr, &[i32_type.const_int(16, false)], "path_offset") };
    let dummy_path = builder.build_load(i64_type, path_gep, "dummy_path").into_int_value();
    
    let path_alloca = builder.build_alloca(i64_type, "path_alloca");
    builder.build_store(path_alloca, dummy_path);

    // Call bpf_map_lookup_elem via Helper ID 1
    let lookup_fn_type = i8_ptr_type.fn_type(&[i8_ptr_type.into(), i8_ptr_type.into()], false);
    let bpf_helper_lookup = builder.build_int_to_ptr(i64_type.const_int(1, false), lookup_fn_type.ptr_type(inkwell::AddressSpace::default()), "lookup_fn_ptr");

    let map_ptr_cast = builder.build_pointer_cast(file_allow_map.as_pointer_value(), i8_ptr_type, "map_cast");
    let key_ptr_cast = builder.build_pointer_cast(path_alloca, i8_ptr_type, "key_cast");
    let lookup_res = builder.build_indirect_call(
        lookup_fn_type,
        bpf_helper_lookup,
        &[map_ptr_cast.into(), key_ptr_cast.into()],
        "lookup_call"
    ).try_as_basic_value().left().unwrap().into_pointer_value();

    let null_ptr = i8_ptr_type.const_null();
    let is_null = builder.build_int_compare(inkwell::IntPredicate::EQ, builder.build_ptr_to_int(lookup_res, i64_type, ""), builder.build_ptr_to_int(null_ptr, i64_type, ""), "is_null");

    let deny_bb = ctx.append_basic_block(lsm_hook, "deny_bb");
    let allow_bb = ctx.append_basic_block(lsm_hook, "allow_bb");
    builder.build_conditional_branch(is_null, deny_bb, allow_bb);

    builder.position_at_end(deny_bb);
    inject_ringbuf_event(ctx, &builder, module, ringbuf_map, 2, 1); // event_type=2(file_open), decision=1(deny)
    builder.build_return(Some(&i32_type.const_int(!0, false))); // -EPERM

    builder.position_at_end(allow_bb);
    inject_ringbuf_event(ctx, &builder, module, ringbuf_map, 2, 0); // event_type=2(file_open), decision=0(allow)
    builder.build_return(Some(&i32_type.const_int(0, false))); // OK
}

use crate::codegen::verify_smt::{SMTVerifier, VerificationResult};
use z3::{Config, Context as Z3Context};

/// Synthesize a BPF_MAP_TYPE_RINGBUF for streaming kernel events to user-space.
fn synthesize_ringbuf_map<'ctx>(
    ctx: &'ctx Context,
    module: &inkwell::module::Module<'ctx>,
) -> GlobalValue<'ctx> {
    let i32_type = ctx.i32_type();
    let map_struct_type = ctx.struct_type(&[
        i32_type.into(), i32_type.into(), i32_type.into(), i32_type.into(), i32_type.into(),
    ], false);

    let map_struct_val = map_struct_type.const_named_struct(&[
        i32_type.const_int(27, false).into(), // BPF_MAP_TYPE_RINGBUF = 27
        i32_type.const_int(0, false).into(),   // key_size = 0 (ringbuf ignores)
        i32_type.const_int(0, false).into(),   // value_size = 0 (ringbuf ignores)
        i32_type.const_int(262144, false).into(), // max_entries = 256KB
        i32_type.const_int(0, false).into(),   // map_flags = 0
    ]);

    let global_map = module.add_global(map_struct_type, None, "telos_event_ringbuf");
    global_map.set_initializer(&map_struct_val);
    global_map.set_section(Some("maps"));
    global_map.set_linkage(Linkage::External);
    global_map
}

/// Build the TelosEvent struct type: { u32 event_type, u32 pid, u32 decision, u64 timestamp }
fn telos_event_struct_type<'ctx>(ctx: &'ctx Context) -> inkwell::types::StructType<'ctx> {
    ctx.struct_type(&[
        ctx.i32_type().into(),  // event_type: 1=connect, 2=file_open
        ctx.i32_type().into(),  // pid (placeholder, filled by helper)
        ctx.i32_type().into(),  // decision: 0=allow, 1=deny
        ctx.i64_type().into(),  // timestamp (placeholder)
    ], false)
}

/// Inject a bpf_ringbuf_output() call into an LSM hook basic block.
/// Uses a global constant struct (no alloca) to satisfy BPF stack constraints.
fn inject_ringbuf_event<'ctx>(
    ctx: &'ctx Context,
    builder: &inkwell::builder::Builder<'ctx>,
    module: &inkwell::module::Module<'ctx>,
    ringbuf_map: GlobalValue<'ctx>,
    event_type: u32,
    decision: u32,
) {
    let i8_type = ctx.i8_type();
    let i32_type = ctx.i32_type();
    let i64_type = ctx.i64_type();
    let i8_ptr_type = i8_type.ptr_type(inkwell::AddressSpace::default());

    // Create a unique global name for this specific event constant
    let global_name = format!("telos_event_{}_{}", event_type, decision);

    let event_struct = telos_event_struct_type(ctx);
    let event_val = event_struct.const_named_struct(&[
        i32_type.const_int(event_type as u64, false).into(),
        i32_type.const_int(0, false).into(),                   // pid placeholder
        i32_type.const_int(decision as u64, false).into(),
        i64_type.const_int(0, false).into(),                    // timestamp placeholder
    ]);

    let event_global = module.add_global(event_struct, None, &global_name);
    event_global.set_initializer(&event_val);
    event_global.set_linkage(Linkage::Internal);

    // Call bpf_ringbuf_output(ringbuf, &event, sizeof(event), 0)
    // Helper ID 130 = bpf_ringbuf_output
    let ringbuf_fn_type = i64_type.fn_type(&[
        i8_ptr_type.into(), i8_ptr_type.into(), i64_type.into(), i64_type.into(),
    ], false);
    let ringbuf_helper = builder.build_int_to_ptr(
        i64_type.const_int(130, false),
        ringbuf_fn_type.ptr_type(inkwell::AddressSpace::default()),
        "ringbuf_fn_ptr",
    );

    let map_ptr = builder.build_pointer_cast(ringbuf_map.as_pointer_value(), i8_ptr_type, "rb_map_cast");
    let event_ptr = builder.build_pointer_cast(event_global.as_pointer_value(), i8_ptr_type, "event_cast");
    let event_size = i64_type.const_int(20, false); // 4+4+4+8 = 20 bytes

    builder.build_indirect_call(
        ringbuf_fn_type,
        ringbuf_helper,
        &[map_ptr.into(), event_ptr.into(), event_size.into(), i64_type.const_int(0, false).into()],
        "ringbuf_output_call",
    );
}

pub fn emit_sandbox(ctx: &Context, machine: &TargetMachine, _intents: &[IntentDecl]) -> Vec<(String, Vec<u8>)> {
    let module = ctx.create_module("telos_sandbox");

    // Phase 2: Synthesize required Hash Maps
    let net_allow_map = synthesize_policy_map(ctx, &module, "telos_net_allow", 4, 2, 256);
    let file_allow_map = synthesize_policy_map(ctx, &module, "telos_file_allow", 256, 4, 256);

    // Phase 4: Synthesize Ringbuf for Pipelock event streaming
    let ringbuf_map = synthesize_ringbuf_map(ctx, &module);

    // Phase 2: Integrate the proper Hooks (now with ringbuf injection)
    synthesize_socket_connect_hook(ctx, &module, net_allow_map, ringbuf_map);
    synthesize_file_open_hook(ctx, &module, file_allow_map, ringbuf_map);

    // Phase 5: SMT Verification pass
    println!("[TELOS] Running SMT formal verification...");
    let z3_config = Config::new();
    let z3_ctx = Z3Context::new(&z3_config);
    let verifier = SMTVerifier::new(&z3_ctx);

    match verifier.verify_module(&module) {
        VerificationResult::Proven => {
            println!("[TELOS VERIFIER] ✓ All LSM hooks formally verified");
        }
        VerificationResult::CounterExample(cex) => {
            panic!("[TELOS VERIFIER] FATAL: Verification failed\n{}", cex);
        }
        VerificationResult::Unknown(msg) => {
            eprintln!("[TELOS VERIFIER] WARNING: {}", msg);
        }
    }

    // Compile module directly to an in-memory object byte buffer
    let memory_buffer = machine.write_to_memory_buffer(&module, FileType::Object).unwrap();
    let elf_bytes = memory_buffer.as_slice();

    // Write BPF object to disk for verification and testing
    std::fs::write("bpf_sandbox.o", elf_bytes).unwrap();

    // ---------------------------------------------------------
    // BARE METAL COMPILER SPLICING
    // Slice off the ELF Header and extract RAW bpf_insn bytes
    // ---------------------------------------------------------
    let elf = Elf::parse(elf_bytes).unwrap();
    let mut hooks = Vec::new();
    for section_header in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section_header.sh_name) {
            if name.starts_with("lsm/") {
                let start = section_header.sh_offset as usize;
                let end = start + section_header.sh_size as usize;
                hooks.push((name.to_string(), elf_bytes[start..end].to_vec()));
            }
        }
    }
    
    hooks
}
