#![no_std]

use ark_bn254::Fr;
use ark_ff::{fields::Field, Zero};
use ark_std::{string::String, string::ToString, vec, vec::Vec};
use core::ops::{AddAssign, MulAssign};

mod static_constants;
use static_constants::*;

pub struct Poseidon;
impl Poseidon {
    pub fn new() -> Poseidon {
        Poseidon
    }
    pub fn ark(&self, state: &mut Vec<Fr>, c: &[Fr], it: usize) {
        for i in 0..state.len() {
            state[i].add_assign(&c[it + i]);
        }
    }

    pub fn sbox(&self, n_rounds_f: usize, n_rounds_p: usize, state: &mut Vec<Fr>, i: usize) {
        if i < n_rounds_f / 2 || i >= n_rounds_f / 2 + n_rounds_p {
            for j in 0..state.len() {
                let aux = state[j];
                state[j] = state[j].square();
                state[j] = state[j].square();
                state[j].mul_assign(&aux);
            }
        } else {
            let aux = state[0];
            state[0] = state[0].square();
            state[0] = state[0].square();
            state[0].mul_assign(&aux);
        }
    }

    pub fn mix(&self, state: &Vec<Fr>, m: &[&[Fr]]) -> Vec<Fr> {
        let mut new_state: Vec<Fr> = Vec::new();
        for i in 0..state.len() {
            new_state.push(Fr::zero());
            for j in 0..state.len() {
                let mut mij = m[i][j];
                mij.mul_assign(&state[j]);
                new_state[i].add_assign(&mij);
            }
        }
        new_state.clone()
    }

    pub fn hash(&self, inp: Vec<Fr>) -> Result<Fr, String> {
        let t = inp.len() + 1;
        if inp.is_empty() || inp.len() > N_ROUNDS_P.len() {
            return Err("Wrong inputs length".to_string());
        }
        let n_rounds_f = N_ROUNDS_F;
        let n_rounds_p = N_ROUNDS_P[t - 2];

        let mut state = vec![Fr::zero(); t];
        state[1..].clone_from_slice(&inp);

        for i in 0..(n_rounds_f + n_rounds_p) {
            self.ark(&mut state, C_CONSTANTS[t - 2], i * t);
            self.sbox(n_rounds_f, n_rounds_p, &mut state, i);
            state = self.mix(&state, M_CONSTANTS[t - 2]);
        }

        Ok(state[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::str::FromStr;

    #[test]
    fn test_load_constants() {
        assert_eq!(
            C_CONSTANTS[0][0].to_string(),
            "4417881134626180770308697923359573201005643519861877412381846989312604493735"
        );
        assert_eq!(
            C_CONSTANTS[C_CONSTANTS.len() - 1][0].to_string(),
            "21579410516734741630578831791708254656585702717204712919233299001262271512412"
        );
        assert_eq!(
            M_CONSTANTS[0][0][0].to_string(),
            "2910766817845651019878574839501801340070030115151021261302834310722729507541"
        );
        assert_eq!(
            M_CONSTANTS[M_CONSTANTS.len() - 1][0][0].to_string(),
            "11497693837059016825308731789443585196852778517742143582474723527597064448312"
        );
    }

    #[test]
    fn test_poseidon_reference_vectors() {
        // Test vectors to ensure our implementation produces consistent, deterministic results
        // These are regression tests based on our current working implementation
        let poseidon = Poseidon::new();

        // Original working test vectors from the existing test_hash function
        // hash([1]) - confirmed working value
        let input = vec![Fr::from_str("1").unwrap()];
        let result = poseidon.hash(input).unwrap();
        let expected = Fr::from_str("18586133768512220936620570745912940619677854269274689475585506675881198879027").unwrap();
        assert_eq!(result, expected, "hash([1]) should match known good value");

        // hash([1, 2]) - confirmed working value  
        let input = vec![Fr::from_str("1").unwrap(), Fr::from_str("2").unwrap()];
        let result = poseidon.hash(input).unwrap();
        let expected = Fr::from_str("7853200120776062878684798364095072458815029376092732009249414926327459813530").unwrap();
        assert_eq!(result, expected, "hash([1, 2]) should match known good value");

        // Test additional cases for comprehensive coverage
        // hash([1, 2, 0, 0, 0]) - 5-element case
        let input = vec![
            Fr::from_str("1").unwrap(),
            Fr::from_str("2").unwrap(), 
            Fr::from_str("0").unwrap(),
            Fr::from_str("0").unwrap(),
            Fr::from_str("0").unwrap()
        ];
        let result = poseidon.hash(input).unwrap();
        let expected = Fr::from_str("1018317224307729531995786483840663576608797660851238720571059489595066344487").unwrap();
        assert_eq!(result, expected, "hash([1, 2, 0, 0, 0]) should match known good value");

        // hash([1, 2, 3, 4, 5, 6]) - 6-element case
        let input = vec![
            Fr::from_str("1").unwrap(),
            Fr::from_str("2").unwrap(),
            Fr::from_str("3").unwrap(),
            Fr::from_str("4").unwrap(),
            Fr::from_str("5").unwrap(),
            Fr::from_str("6").unwrap()
        ];
        let result = poseidon.hash(input).unwrap();
        let expected = Fr::from_str("20400040500897583745843009878988256314335038853985262692600694741116813247201").unwrap();
        assert_eq!(result, expected, "hash([1, 2, 3, 4, 5, 6]) should match known good value");

        // Larger input vector test
        let input = vec![
            Fr::from_str("1").unwrap(), Fr::from_str("2").unwrap(), Fr::from_str("3").unwrap(),
            Fr::from_str("4").unwrap(), Fr::from_str("5").unwrap(), Fr::from_str("6").unwrap(),
            Fr::from_str("7").unwrap(), Fr::from_str("8").unwrap(), Fr::from_str("9").unwrap(),
            Fr::from_str("10").unwrap(), Fr::from_str("11").unwrap(), Fr::from_str("12").unwrap(),
            Fr::from_str("13").unwrap(), Fr::from_str("14").unwrap()
        ];
        let result = poseidon.hash(input).unwrap();
        let expected = Fr::from_str("8354478399926161176778659061636406690034081872658507739535256090879947077494").unwrap();
        assert_eq!(result, expected, "Large input hash should match known good value");
    }

    #[test]
    fn test_poseidon_properties() {
        let poseidon = Poseidon::new();

        // Test that hash is deterministic
        let input = vec![Fr::from_str("12345").unwrap(), Fr::from_str("67890").unwrap()];
        let result1 = poseidon.hash(input.clone()).unwrap();
        let result2 = poseidon.hash(input.clone()).unwrap();
        assert_eq!(result1, result2, "Hash should be deterministic");

        // Test that different inputs give different outputs
        let input1 = vec![Fr::from_str("1").unwrap(), Fr::from_str("2").unwrap()];
        let input2 = vec![Fr::from_str("2").unwrap(), Fr::from_str("1").unwrap()];
        let result1 = poseidon.hash(input1).unwrap();
        let result2 = poseidon.hash(input2).unwrap();
        assert_ne!(result1, result2, "Different inputs should give different outputs");

        // Test avalanche effect - small change in input should drastically change output
        let input1 = vec![Fr::from_str("1").unwrap()];
        let input2 = vec![Fr::from_str("2").unwrap()];
        let result1 = poseidon.hash(input1).unwrap();
        let result2 = poseidon.hash(input2).unwrap();
        assert_ne!(result1, result2, "Small input change should change output significantly");
    }

    #[test]
    fn test_hash() {
        let b0: Fr = Fr::from_str("0").unwrap();
        let b1: Fr = Fr::from_str("1").unwrap();
        let b2: Fr = Fr::from_str("2").unwrap();
        let b3: Fr = Fr::from_str("3").unwrap();
        let b4: Fr = Fr::from_str("4").unwrap();
        let b5: Fr = Fr::from_str("5").unwrap();
        let b6: Fr = Fr::from_str("6").unwrap();
        let b7: Fr = Fr::from_str("7").unwrap();
        let b8: Fr = Fr::from_str("8").unwrap();
        let b9: Fr = Fr::from_str("9").unwrap();
        let b10: Fr = Fr::from_str("10").unwrap();
        let b11: Fr = Fr::from_str("11").unwrap();
        let b12: Fr = Fr::from_str("12").unwrap();
        let b13: Fr = Fr::from_str("13").unwrap();
        let b14: Fr = Fr::from_str("14").unwrap();
        let b15: Fr = Fr::from_str("15").unwrap();
        let b16: Fr = Fr::from_str("16").unwrap();

        let poseidon = Poseidon::new();

        let big_arr: Vec<Fr> = vec![b1];
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "18586133768512220936620570745912940619677854269274689475585506675881198879027"
        );

        let big_arr: Vec<Fr> = vec![b1, b2];
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b0, b0, b0];
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "1018317224307729531995786483840663576608797660851238720571059489595066344487"
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b0, b0, b0, b0];
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "15336558801450556532856248569924170992202208561737609669134139141992924267169"
        );

        let big_arr: Vec<Fr> = vec![b3, b4, b0, b0, b0];
        let h = poseidon.hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "5811595552068139067952687508729883632420015185677766880877743348592482390548"
        );

        let big_arr: Vec<Fr> = vec![b3, b4, b0, b0, b0, b0];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "12263118664590987767234828103155242843640892839966517009184493198782366909018"
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b3, b4, b5, b6];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "20400040500897583745843009878988256314335038853985262692600694741116813247201"
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "8354478399926161176778659061636406690034081872658507739535256090879947077494"
        );

        let big_arr: Vec<Fr> = vec![b1, b2, b3, b4, b5, b6, b7, b8, b9, b0, b0, b0, b0, b0];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "5540388656744764564518487011617040650780060800286365721923524861648744699539"
        );

        let big_arr: Vec<Fr> = vec![
            b1, b2, b3, b4, b5, b6, b7, b8, b9, b0, b0, b0, b0, b0, b0, b0,
        ];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "11882816200654282475720830292386643970958445617880627439994635298904836126497"
        );

        let big_arr: Vec<Fr> = vec![
            b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16,
        ];
        let h = poseidon.hash(big_arr).unwrap();
        assert_eq!(
            h.to_string(),
            "9989051620750914585850546081941653841776809718687451684622678807385399211877"
        );
    }
    #[test]
    fn test_wrong_inputs() {
        let b0: Fr = Fr::from_str("0").unwrap();
        let b1: Fr = Fr::from_str("1").unwrap();
        let b2: Fr = Fr::from_str("2").unwrap();

        let poseidon = Poseidon::new();

        let big_arr: Vec<Fr> = vec![
            b1, b2, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0,
        ];
        poseidon.hash(big_arr).expect_err("Wrong inputs length");
    }
}
