use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    poseidon::{hashv, Endianness, Parameters},
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    match instruction_data[0] {
        0 => {
            // Poseidon hash with 1 input using native syscall
            let input = &instruction_data[1..];
            if input.len() != 32 {
                return Err(ProgramError::InvalidInstructionData);
            }
            
            // Use Solana's native Poseidon syscall
            let result = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &[input])
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            msg!("Poseidon1({} bytes): {:?}", input.len(), &result.to_bytes()[..8]);
        }
        1 => {
            // Poseidon hash with 2 inputs using native syscall
            let input = &instruction_data[1..];
            if input.len() != 64 {
                return Err(ProgramError::InvalidInstructionData);
            }
            
            let bytes1 = &input[0..32];
            let bytes2 = &input[32..64];
            
            // Use Solana's native Poseidon syscall with 2 inputs
            let result = hashv(Parameters::Bn254X5, Endianness::LittleEndian, &[bytes1, bytes2])
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            msg!("Poseidon2({} bytes): {:?}", input.len(), &result.to_bytes()[..8]);
        }
        _ => {
            return Err(ProgramError::InvalidInstructionData);
        }
    }
    
    Ok(())
}