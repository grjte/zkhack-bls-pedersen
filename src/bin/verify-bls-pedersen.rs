use ark_crypto_primitives::crh::pedersen::bytes_to_bits;
use bls_pedersen::bls::verify;
use bls_pedersen::data::puzzle_data;
use bls_pedersen::PUZZLE_DESCRIPTION;
use prompt::{puzzle, welcome};
extern crate nalgebra as na;
use na::SMatrix;

type MsgsMatrix = SMatrix<bool, 256, 256>;
type MsgVector = SMatrix<bool, 1, 256>;

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);
    let (pk, ms, sigs) = puzzle_data();
    for (m, sig) in ms.iter().zip(sigs.iter()) {
        verify(pk, m, *sig);
    }

    /* SOLUTION NOTES */
    // There's no working solution here, but I'm new to the space and submitting weekly was part of my personal commitment to this learning process. Please see my theoretical solution & attempt below.
    // This puzzle has been a good vehicle for learning. Thanks Puzzlemaster Kobi and creators!

    /* ----- theoretical approach ----- */
    // set message m to my username
    // find the linear combination of the leaked ms that gives m
    // use that LC to create a sig that is LC of the leaked sigs.
    // This will be a valid sig for m

    // intuitively, this theoretical solution is based on the following:
    // consider pedersen hash over 2-bit message space
    // let the leaked messages lm0 = 01, lm1 = 10 and denote the corresponding leaked signatures sig0, sig1
    // let m = 11 be the message for which we want a signature
    // let the parameters used for the pedersen hash be p = [p0, p1], giving us the following hashes of lm0, lm1
    //   H(lm0) = 0*p0 + 1*p1 = p1
    //   H(lm1) = 1*p0 + 0*p1 = p0
    // note that m = LC of lm0,lm1 with alpha_1 = 1, alpha_2 = 1
    //   alpha_1*(lm0) + alpha_2*(lm1) = 1(01) + 1(10) = 11
    // note that H(m) is LC of H(lm0), H(lm1) w/ the same coefficients alpha_1 = 1, alpha_2 = 1
    //   H(m) = 1*p0 + 1*p1 = p0 + p1 =  H(lm0) + H(lm1)
    //   => sigm = [sk] * H(m) = [sk] * (H(lm0) +  H(lm1)) = [sk]*H(lm0) + [sk]*H(lm1) = sig0 + sig1
    // therefore the LC of of the signatures will give a valid signature for message m

    /* ----- implementation (incomplete) ----- */
    // 0. create my message
    let m = "grjte".to_string().into_bytes();

    // 1. represent message as a 256x1 bit vector
    let m_b2hash = blake2s_simd::blake2s(&m);
    let _matrix_m = MsgVector::from_vec(bytes_to_bits(m_b2hash.as_bytes()));

    // 2. put the leaked messages into a 256x256 bit matrix where each ij is a message bit
    // accumulate into an array of vectors first (there's probably a better way to do this)
    let mut msg_vecs: [MsgVector; 256] = [MsgVector::from_element(false); 256];
    for i in 0..256 {
        let b2hash = blake2s_simd::blake2s(&ms[i]);
        let msg_vector = MsgVector::from_vec(bytes_to_bits(b2hash.as_bytes()));
        msg_vecs[i] = msg_vector;
    }
    // matrix of all leaked messages in bits, formed from rows
    let _matrix_ms = MsgsMatrix::from_rows(&msg_vecs);

    // 3. solve using nalgebra

    // 4. calculate signature
    // let sig;
    // for (s, a) in sigs.iter().zip(va.iter()) {
    //     if *a {
    //         sig += s;
    //     }
    // }

    // 5. verify
    // verify(pk, m, sig);
}
