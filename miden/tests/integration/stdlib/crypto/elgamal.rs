use super::{build_test, Felt};
use crate::stdlib::math::ecgfp5::base_field::{bv_or, Ext5};
use std::{cmp::PartialEq, ops::{Mul, Add}};
use crate::stdlib::math::ecgfp5::*;
use crate::stdlib::math::ecgfp5::scalar_field::Scalar;
use vm_core::{FieldElement, StarkField};

#[test]
fn test_elgamal_keygen() {
    let p0 = group::ECExt5 {
        x: Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ),
        y: Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ) * Ext5::from_int(4),
        point_at_infinity: Felt::ZERO,
    };

    let e = [
        666904740u32,
        1257318652u32,
        4031728122u32,
        3689598853u32,
        703808805u32,
        386793741u32,
        2898811333u32,
        4092670716u32,
        1596344924u32,
        1692681010u32,
    ];
    let q1 = p0.scalar_mul(&e);

    let mut stack = [
        666904740u64,
        1257318652u64,
        4031728122u64,
        3689598853u64,
        703808805u64,
        386793741u64,
        2898811333u64,
        4092670716u64,
        1596344924u64,
        1692681010u64,
    ];

    println!("{:?}", q1);

    // let source = "
    //     use.std::math::ecgfp5::group

    //     begin
    //         exec.group::mul
    //     end";

    // ";
    let source = "
        use.std::crypto::elgamal_ecgfp5

        begin
            exec.elgamal_ecgfp5::gen_privatekey
        end

    ";

    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    println!("{:?}", strace);

    
}

#[test]
fn test_elgamal_encrypt() {
    //inputs r, M, H
    //r is 10 limbs
    //H and M are both x and y at point inf
    //11*2 inputs
    let e = [
        666904740u32,
        1257318652u32,
        3031728122u32,
        2689598853u32,
        703808805u32,
        386793741u32,
        2898811333u32,
        4092670716u32,
        1596344924u32,
        1692681010u32,
    ];
    let r = [
        666904740u32,
        1257318652u32,
        4031728122u32,
        3689598853u32,
        703808805u32,
        386793741u32,
        2898811333u32,
        4092670716u32,
        1596344924u32,
        1692681010u32,
    ];

    let p0 = group::ECExt5 {
        x: Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ),
        y: Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ) * Ext5::from_int(4),
        point_at_infinity: Felt::ZERO,
    };
    let police = [
        666904740u32,
        257318652u32,
        4031728122u32,
        3689598853u32,
        703808805u32,
        386793741u32,
        2898811333u32,
        4092670716u32,
        1596344924u32,
        1692681010u32,
    ];

    let pm = p0.scalar_mul(&police);


    let ca = p0.scalar_mul(&r);
    let h = p0.scalar_mul(&e);
    let rh = h.scalar_mul(&r);
    let cb = pm.add(rh);

    println!("{:?}", ca);
    // println!("{:?} {:?}", ca, cb);

    let source = "
        use.std::crypto::elgamal_ecgfp5

        begin
            exec.elgamal_ecgfp5::encrypt
        end

    ";

    let mut stack = [
        h.x.a0.as_int(),
        h.x.a1.as_int(),
        h.x.a2.as_int(),
        h.x.a3.as_int(),
        h.x.a4.as_int(),
        h.y.a0.as_int(),
        h.y.a1.as_int(),
        h.y.a2.as_int(),
        h.y.a3.as_int(),
        h.y.a4.as_int(),
        h.point_at_infinity.as_int(),
        pm.x.a0.as_int(),
        pm.x.a1.as_int(),
        pm.x.a2.as_int(),
        pm.x.a3.as_int(),
        pm.x.a4.as_int(),
        pm.y.a0.as_int(),
        pm.y.a1.as_int(),
        pm.y.a2.as_int(),
        pm.y.a3.as_int(),
        pm.y.a4.as_int(),
        pm.point_at_infinity.as_int(),
        r[0] as u64,
        r[1] as u64,
        r[2] as u64,
        r[3] as u64,
        r[4] as u64,
        r[5] as u64,
        r[6] as u64,
        r[7] as u64,
        r[8] as u64,
        r[9] as u64,
    ];

    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    println!("{:?}", strace);

}

#[test]
fn test_elgamal_remask() {
    // Also known as rerandomisation
    // inputs r, H, Ca, Cb
    // r is 10 limbs
    // H, Ca, and Cb are 11 inputs each
    let e = [
        666904740u32,
        1257318652u32,
        3031728122u32,
        2689598853u32,
        703808805u32,
        386793741u32,
        2898811333u32,
        4092670716u32,
        1596344924u32,
        1692681010u32,
    ];
    let r = [
        111111111u32,
        1257318652u32,
        4031728122u32,
        3689598853u32,
        703808805u32,
        386793741u32,
        2898811333u32,
        4092670716u32,
        1596344924u32,
        1692681010u32,
    ];

    let p0 = group::ECExt5 {
        x: Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ),
        y: Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ) * Ext5::from_int(4),
        point_at_infinity: Felt::ZERO,
    };

    // the plaintext message
    let plaintext_pt = [
        666904740u32,
        257318652u32,
        4031728122u32,
        3689598853u32,
        703808805u32,
        386793741u32,
        2898811333u32,
        4092670716u32,
        1596344924u32,
        1692681010u32,
    ];

    let pm = p0.scalar_mul(&plaintext_pt);


    let ca = p0.scalar_mul(&r);
    let h = p0.scalar_mul(&e);
    let rh = h.scalar_mul(&r);
    let cb = pm.add(rh);

    //println!("{:?}", ca);
    // println!("{:?} {:?}", ca, cb);

    let source = "
        use.std::crypto::elgamal_ecgfp5

        begin
            exec.elgamal_ecgfp5::remask
        end
    ";

    let mut stack = [
        h.x.a0.as_int(),
        h.x.a1.as_int(),
        h.x.a2.as_int(),
        h.x.a3.as_int(),
        h.x.a4.as_int(),
        h.y.a0.as_int(),
        h.y.a1.as_int(),
        h.y.a2.as_int(),
        h.y.a3.as_int(),
        h.y.a4.as_int(),
        h.point_at_infinity.as_int(),
        pm.x.a0.as_int(),
        pm.x.a1.as_int(),
        pm.x.a2.as_int(),
        pm.x.a3.as_int(),
        pm.x.a4.as_int(),
        pm.y.a0.as_int(),
        pm.y.a1.as_int(),
        pm.y.a2.as_int(),
        pm.y.a3.as_int(),
        pm.y.a4.as_int(),
        pm.point_at_infinity.as_int(),
        r[0] as u64,
        r[1] as u64,
        r[2] as u64,
        r[3] as u64,
        r[4] as u64,
        r[5] as u64,
        r[6] as u64,
        r[7] as u64,
        r[8] as u64,
        r[9] as u64,
    ];

    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    println!("{:?}", strace);

}
