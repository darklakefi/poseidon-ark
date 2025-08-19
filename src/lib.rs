use solana_program::poseidon::{hashv, Endianness, Parameters};

pub struct Poseidon;

impl Poseidon {
    pub fn new() -> Poseidon {
        Poseidon
    }

    /// Hash function that uses Solana's native Poseidon syscall
    pub fn hash_bytes(&self, inputs: &[&[u8; 32]]) -> Result<[u8; 32], String> {
        if inputs.is_empty() {
            return Err("Empty input".to_string());
        }
        
        // Convert &[u8; 32] to &[u8] for the syscall
        let byte_slices: Vec<&[u8]> = inputs.iter().map(|&arr| &arr[..]).collect();
        
        // Use Solana's native Poseidon syscall
        let result = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &byte_slices)
            .map_err(|_| "Poseidon syscall failed".to_string())?;
            
        Ok(result.to_bytes())
    }
}