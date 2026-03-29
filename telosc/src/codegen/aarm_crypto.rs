use inkwell::context::Context;
use inkwell::builder::Builder;
use inkwell::values::IntValue;

fn rotl<'ctx>(ctx: &'ctx Context, builder: &Builder<'ctx>, x: IntValue<'ctx>, b: u64) -> IntValue<'ctx> {
    let i64_type = ctx.i64_type();
    let shift_left = builder.build_left_shift(x, i64_type.const_int(b, false), "");
    let shift_right = builder.build_right_shift(x, i64_type.const_int(64 - b, false), false, "");
    builder.build_or(shift_left, shift_right, "")
}

fn sipround<'ctx>(ctx: &'ctx Context, builder: &Builder<'ctx>, v0: &mut IntValue<'ctx>, v1: &mut IntValue<'ctx>, v2: &mut IntValue<'ctx>, v3: &mut IntValue<'ctx>) {
    *v0 = builder.build_int_add(*v0, *v1, "");
    *v1 = rotl(ctx, builder, *v1, 13);
    *v1 = builder.build_xor(*v1, *v0, "");
    *v0 = rotl(ctx, builder, *v0, 32);
    
    *v2 = builder.build_int_add(*v2, *v3, "");
    *v3 = rotl(ctx, builder, *v3, 16);
    *v3 = builder.build_xor(*v3, *v2, "");
    
    *v0 = builder.build_int_add(*v0, *v3, "");
    *v3 = rotl(ctx, builder, *v3, 21);
    *v3 = builder.build_xor(*v3, *v0, "");
    
    *v2 = builder.build_int_add(*v2, *v1, "");
    *v1 = rotl(ctx, builder, *v1, 17);
    *v1 = builder.build_xor(*v1, *v2, "");
    *v2 = rotl(ctx, builder, *v2, 32);
}

pub fn synthesize_siphash_receipt<'ctx>(
    ctx: &'ctx Context,
    builder: &Builder<'ctx>,
    message: IntValue<'ctx>, 
    mac_key: IntValue<'ctx>
) -> IntValue<'ctx> {
    let i64_type = ctx.i64_type();
    
    // SipHash magical constants
    let mut v0 = builder.build_xor(mac_key, i64_type.const_int(0x736f6d6570736575, false), "v0");
    let mut v1 = builder.build_xor(mac_key, i64_type.const_int(0x646f72616e646f6d, false), "v1");
    let mut v2 = builder.build_xor(mac_key, i64_type.const_int(0x6c7967656e657261, false), "v2");
    let mut v3 = builder.build_xor(mac_key, i64_type.const_int(0x7465646279746573, false), "v3");
    
    v3 = builder.build_xor(v3, message, "");
    
    sipround(ctx, builder, &mut v0, &mut v1, &mut v2, &mut v3);
    sipround(ctx, builder, &mut v0, &mut v1, &mut v2, &mut v3);
    
    v0 = builder.build_xor(v0, message, "");
    v2 = builder.build_xor(v2, i64_type.const_int(0xff, false), "");
    
    sipround(ctx, builder, &mut v0, &mut v1, &mut v2, &mut v3);
    sipround(ctx, builder, &mut v0, &mut v1, &mut v2, &mut v3);
    sipround(ctx, builder, &mut v0, &mut v1, &mut v2, &mut v3);
    sipround(ctx, builder, &mut v0, &mut v1, &mut v2, &mut v3);
    
    let h1 = builder.build_xor(v0, v1, "");
    let h2 = builder.build_xor(h1, v2, "");
    builder.build_xor(h2, v3, "receipt_hash")
}
