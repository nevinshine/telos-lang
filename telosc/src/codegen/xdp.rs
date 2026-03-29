use inkwell::context::Context;
use inkwell::module::{Module, Linkage};
use inkwell::values::{FunctionValue, GlobalValue};
use inkwell::IntPredicate;

/// Synthesizes the BPF_PROG_TYPE_XDP hardware drop bridge to enforce capability bounds natively on the NIC.
pub fn synthesize_xdp_bridge<'ctx>(
    ctx: &'ctx Context,
    module: &Module<'ctx>,
    net_allow_map: GlobalValue<'ctx>,
) -> FunctionValue<'ctx> {
    let i8_type = ctx.i8_type();
    let i16_type = ctx.i16_type();
    let i32_type = ctx.i32_type();
    let i64_type = ctx.i64_type();
    let void_ptr_type = i8_type.ptr_type(inkwell::AddressSpace::default());

    // Standard XDP return thresholds
    let xdp_drop = i32_type.const_int(1, false);
    let xdp_pass = i32_type.const_int(2, false);

    // In BPF, xdp_md pointers are structurally provided exactly as u32 offsets, but clang compiles them 
    // dynamically internally. For our raw generic synthesis, data and data_end are 32-bit fields.
    let xdp_md_type = ctx.struct_type(&[i32_type.into(), i32_type.into()], false);
    let xdp_md_ptr_type = xdp_md_type.ptr_type(inkwell::AddressSpace::default());

    let fn_type = i32_type.fn_type(&[xdp_md_ptr_type.into()], false);
    let xdp_fn = module.add_function("telos_xdp_bridge", fn_type, Some(Linkage::External));
    xdp_fn.set_section(Some("xdp/telos_bridge"));
    
    let basic_block = ctx.append_basic_block(xdp_fn, "entry");
    let builder = ctx.create_builder();
    builder.position_at_end(basic_block);

    let ctx_arg = xdp_fn.get_nth_param(0).unwrap().into_pointer_value();

    // Read ctx->data
    let data_ptr_gep = unsafe { builder.build_gep(xdp_md_type, ctx_arg, &[i32_type.const_zero(), i32_type.const_zero()], "data_ptr_gep") };
    let data_val32 = builder.build_load(i32_type, data_ptr_gep, "data_val32").into_int_value();
    let data_ptr = builder.build_int_to_ptr(data_val32, void_ptr_type, "data_ptr");

    // Read ctx->data_end
    let data_end_ptr_gep = unsafe { builder.build_gep(xdp_md_type, ctx_arg, &[i32_type.const_zero(), i32_type.const_int(1, false)], "data_end_ptr_gep") };
    let data_end_val32 = builder.build_load(i32_type, data_end_ptr_gep, "data_end_val32").into_int_value();

    // Eth (14) + IPv4 (20) + TCP (20) = 54 bytes
    let min_len = i32_type.const_int(54, false);
    let packet_end_req = builder.build_int_add(data_val32, min_len, "packet_end_req");
    
    let is_too_short = builder.build_int_compare(IntPredicate::UGT, packet_end_req, data_end_val32, "is_too_short");
    
    let parse_bb = ctx.append_basic_block(xdp_fn, "parse_bb");
    let pass_bb = ctx.append_basic_block(xdp_fn, "pass_bb");
    
    builder.build_conditional_branch(is_too_short, pass_bb, parse_bb);

    // --- Raw Packet Header Slicing Block ---
    builder.position_at_end(parse_bb);

    // Extract TCP Destination Port natively from raw byte offsets: 
    // Eth(14) + IPv4(20) + TCP DPORT Offset(2) = Byte 36
    let dport_gep = unsafe { builder.build_gep(i8_type, data_ptr, &[i32_type.const_int(36, false)], "") };
    let dport_ptr = builder.build_pointer_cast(dport_gep, i16_type.ptr_type(inkwell::AddressSpace::default()), "dport_ptr");
    let dport = builder.build_load(i16_type, dport_ptr, "dport").into_int_value();

    // Reconstruct the BPF map lookup helper boundary
    let map_lookup_geom = i64_type.fn_type(&[void_ptr_type.into(), void_ptr_type.into()], false);
    let map_lookup_fn = module.get_function("bpf_map_lookup_elem").unwrap_or_else(|| module.add_function("bpf_map_lookup_elem", map_lookup_geom, None));
    
    let key_alloca = builder.build_alloca(i16_type, "key_alloca");
    builder.build_store(key_alloca, dport);
    
    let map_ptr_cast = builder.build_pointer_cast(net_allow_map.as_pointer_value(), void_ptr_type, "");
    let key_ptr_cast = builder.build_pointer_cast(key_alloca, void_ptr_type, "");
    
    let lookup_res = builder.build_direct_call(map_lookup_fn, &[map_ptr_cast.into(), key_ptr_cast.into()], "lookup_res").try_as_basic_value().left().unwrap().into_int_value();
    
    let is_null = builder.build_int_compare(IntPredicate::EQ, lookup_res, i64_type.const_zero(), "is_null");
    
    let drop_bb = ctx.append_basic_block(xdp_fn, "drop_bb");
    
    // Fast-path strict enforcement: unauthorized packets matching capability constraints drop instantly!
    builder.build_conditional_branch(is_null, drop_bb, pass_bb);

    // --- Hardware Drop Isolation ---
    builder.position_at_end(drop_bb);
    builder.build_return(Some(&xdp_drop));

    // --- Pass Legitimate Network Traffic ---
    builder.position_at_end(pass_bb);
    builder.build_return(Some(&xdp_pass));

    xdp_fn
}
