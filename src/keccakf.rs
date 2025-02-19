use crate::{Buffer, Permutation};

const ROUNDS: usize = 24;

const RC: [u64; ROUNDS] = [
    1u64,
    0x8082u64,
    0x800000000000808au64,
    0x8000000080008000u64,
    0x808bu64,
    0x80000001u64,
    0x8000000080008081u64,
    0x8000000000008009u64,
    0x8au64,
    0x88u64,
    0x80008009u64,
    0x8000000au64,
    0x8000808bu64,
    0x800000000000008bu64,
    0x8000000000008089u64,
    0x8000000000008003u64,
    0x8000000000008002u64,
    0x8000000000000080u64,
    0x800au64,
    0x800000008000000au64,
    0x8000000080008081u64,
    0x8000000000008080u64,
    0x80000001u64,
    0x8000000080008008u64,
];

#[cfg(not(target_arch = "valida"))]
keccak_function!("`keccak-f[1600, 24]`", keccakf, ROUNDS, RC);

fn u64_to_u8_le(buffer: [u64; 25]) -> [u8; 200] {
    let mut result = [0u8; 200];
    for i in 0..25 {
        let bytes = buffer[i].to_le_bytes();
        let start = i * 8;
        result[start..start+8].copy_from_slice(&bytes);
    }
    result
}
fn u8_to_u64_le(buffer: [u8; 200]) -> [u64; 25] {
    let mut result = [0u64; 25];
    for i in 0..25 {
        let start = i * 8;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&buffer[start..start+8]);
        result[i] = u64::from_le_bytes(bytes);
    }
    result
}

#[cfg(target_arch = "valida")]
extern "C" {
    fn keccak_permutation(buffer: *mut u8);
}
#[cfg(target_arch = "valida")]
/// Performs the Keccak-f[1600] permutation on the given buffer using Valida's keccak chip for the permutation.
/// 
/// This is the core permutation function used in the Keccak hash function family.
/// The buffer represents the 1600-bit state as an array of 25 64-bit words.
/// 
/// # Arguments
/// * `buffer` - Mutable reference to an array of 25 u64 values representing the state
pub fn keccakf(buffer: &mut [u64; 25]) {
    let buffer_input_u8 = u64_to_u8_le(*buffer);
    let mut buffer_with_result = [0u8; 400];
    // Copy input to first half
    buffer_with_result[..200].copy_from_slice(&buffer_input_u8);
    unsafe {
        keccak_permutation(buffer_with_result.as_mut_ptr());
    }
    
    // Get result from second half where the builtin wrote it
    let buffer_output_u8 = {
        let mut temp = [0u8; 200];
        temp.copy_from_slice(&buffer_with_result[200..400]);
        temp
    };
    
    *buffer = u8_to_u64_le(buffer_output_u8);
}

pub struct KeccakF;

impl Permutation for KeccakF {
    fn execute(buffer: &mut Buffer) {
        keccakf(buffer.words());
    }
}
