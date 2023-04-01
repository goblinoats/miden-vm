use super::{build_test, Felt};
use crate::stdlib::math::ecgfp5::base_field::Ext5;
use std::ops::Add;
use crate::stdlib::math::ecgfp5::*;
use vm_core::{FieldElement, StarkField};

use rand_utils::rand_array;
fn gen_random_private_key() -> [u32; 10] {
    rand_array::<u32, 10>()
}

fn get_generator() -> group::ECExt5 {
    group::ECExt5 {
        x: base_field::Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ),
        y: base_field::Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ) * base_field::Ext5::from_int(4),
        point_at_infinity: Felt::ZERO,
    }
}

#[test]
fn test_elgamal_keygen() {
    let gen = get_generator();
    let private_key = gen_random_private_key();
    let q1 = gen.scalar_mul(&private_key);

    let mut stack: [u64; 10] = private_key.iter().map(|x| *x as u64).collect::<Vec<u64>>().try_into().unwrap();

    let source = "
        use.std::crypto::elgamal_ecgfp5

        begin
            exec.elgamal_ecgfp5::gen_privatekey
        end
    ";

    stack.reverse();

    let test = build_test!(source, &stack);
    let binding = test.execute().unwrap();
    let strace = binding.stack_outputs().stack();
    let pk_st = group::ECExt5 {
        x: Ext5::new(
            strace[0],
            strace[1],
            strace[2],
            strace[3],
            strace[4]
        ),
        y: Ext5::new(
            strace[5],
            strace[6],
            strace[7],
            strace[8],
            strace[9]
        ),
        point_at_infinity: Felt::ZERO,
    };

    assert_eq!(q1, pk_st);
}

#[test]
fn test_elgamal_encrypt() {
    //inputs r, M, H
    //r is 10 limbs
    //H and M are both x and y at point inf
    //11*2 inputs
    let private_key = gen_random_private_key();
    let r = gen_random_private_key();

    let gen = get_generator();
    let plaintext_scalar = [
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

    let pm = gen.scalar_mul(&plaintext_scalar);


    let ca = gen.scalar_mul(&r);
    let h = gen.scalar_mul(&private_key);
    let rh = h.scalar_mul(&r);
    let cb = pm.add(rh);

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
    let binding = test.execute().unwrap();
    let strace = binding.stack_outputs().stack();

    let ca_st = group::ECExt5 {
        x: Ext5::new(
            strace[0],
            strace[1],
            strace[2],
            strace[3],
            strace[4]
        ),
        y: Ext5::new(
            strace[5],
            strace[6],
            strace[7],
            strace[8],
            strace[9]
        ),
        point_at_infinity: Felt::ZERO,
    };

    let cb_st = group::ECExt5 {
        x: Ext5::new(
            strace[11],
            strace[12],
            strace[13],
            strace[14],
            strace[15]
        ),
        y: Ext5::new(
            strace[16],
            strace[17],
            strace[18],
            strace[19],
            strace[20]
        ),
        point_at_infinity: Felt::ZERO,
    };

    assert_eq!(ca_st, ca);
    assert_eq!(cb_st, cb);
}

#[test]
fn test_elgamal_remask() {
    // Also known as rerandomisation
    // inputs r, H, Cb, Ca
    // The private key
    let private_key = gen_random_private_key();
    let r = gen_random_private_key();
    let r_prime = gen_random_private_key();

    let gen = get_generator();
    let plaintext_scalar = [
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

    let pm = gen.scalar_mul(&plaintext_scalar);

    let ca = gen.scalar_mul(&r);
    let h = gen.scalar_mul(&private_key);
    let rh = h.scalar_mul(&r);
    let cb = pm.add(rh);

    // ca and cb are the original plaintext
    let r_prime_g = gen.scalar_mul(&r_prime);
    let r_prime_h = h.scalar_mul(&r_prime);
    let c_prime_a = ca.add(r_prime_g);
    let c_prime_b = cb.add(r_prime_h);

    let source = "
        use.std::crypto::elgamal_ecgfp5

        begin
            exec.elgamal_ecgfp5::remask_ca
        end
    ";

    let mut stack = [
        ca.x.a0.as_int(),
        ca.x.a1.as_int(),
        ca.x.a2.as_int(),
        ca.x.a3.as_int(),
        ca.x.a4.as_int(),
        ca.y.a0.as_int(),
        ca.y.a1.as_int(),
        ca.y.a2.as_int(),
        ca.y.a3.as_int(),
        ca.y.a4.as_int(),
        ca.point_at_infinity.as_int(),
        r_prime[0] as u64,
        r_prime[1] as u64,
        r_prime[2] as u64,
        r_prime[3] as u64,
        r_prime[4] as u64,
        r_prime[5] as u64,
        r_prime[6] as u64,
        r_prime[7] as u64,
        r_prime[8] as u64,
        r_prime[9] as u64,
    ];
    stack.reverse();

    let test = build_test!(source, &stack);
    let binding = test.execute().unwrap();
    let strace = binding.stack_outputs().stack();

    let _r_prime_g_st = group::ECExt5 {
        x: Ext5::new(
            strace[0],
            strace[1],
            strace[2],
            strace[3],
            strace[4]
        ),
        y: Ext5::new(
            strace[5],
            strace[6],
            strace[7],
            strace[8],
            strace[9]
        ),
        point_at_infinity: Felt::ZERO,
    };

    let c_prime_a_st = group::ECExt5 {
        x: Ext5::new(
            strace[0],
            strace[1],
            strace[2],
            strace[3],
            strace[4]
        ),
        y: Ext5::new(
            strace[5],
            strace[6],
            strace[7],
            strace[8],
            strace[9]
        ),
        point_at_infinity: Felt::ZERO,
    };

    assert_eq!(c_prime_a, c_prime_a_st);
    
    let source = "
        use.std::crypto::elgamal_ecgfp5

        begin
            exec.elgamal_ecgfp5::remask_cb
        end
    ";

    let mut stack = [
        cb.x.a0.as_int(),
        cb.x.a1.as_int(),
        cb.x.a2.as_int(),
        cb.x.a3.as_int(),
        cb.x.a4.as_int(),
        cb.y.a0.as_int(),
        cb.y.a1.as_int(),
        cb.y.a2.as_int(),
        cb.y.a3.as_int(),
        cb.y.a4.as_int(),
        cb.point_at_infinity.as_int(),
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
        r_prime[0] as u64,
        r_prime[1] as u64,
        r_prime[2] as u64,
        r_prime[3] as u64,
        r_prime[4] as u64,
        r_prime[5] as u64,
        r_prime[6] as u64,
        r_prime[7] as u64,
        r_prime[8] as u64,
        r_prime[9] as u64,
    ];
    stack.reverse();

    let test = build_test!(source, &stack);
    let binding = test.execute().unwrap();
    let strace = binding.stack_outputs().stack();

    let c_prime_b_st = group::ECExt5 {
        x: Ext5::new(
            strace[0],
            strace[1],
            strace[2],
            strace[3],
            strace[4]
        ),
        y: Ext5::new(
            strace[5],
            strace[6],
            strace[7],
            strace[8],
            strace[9]
        ),
        point_at_infinity: Felt::ZERO,
    };

    assert_eq!(c_prime_b, c_prime_b_st);
}
