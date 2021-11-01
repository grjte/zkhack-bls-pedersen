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

    /* Your solution here! */
    /*
      let sig = ...;
      let m = your username;
      verify(pk, m, sig);
    */

    /* ----- process/progress/attempts below ----- */

    /*************** APPROACH 3: ***************/
    // select m (my username)
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

    // steps:
    // 0. create my message
    let m = "grjte".to_string().into_bytes();
    // 1. represent message as a 256x1 matrix
    let m_b2hash = blake2s_simd::blake2s(&m);
    let matrix_m = MsgVector::from_vec(bytes_to_bits(m_b2hash.as_bytes()));

    // 2. put the leaked messages into a 256x256 matrix where each ij is a message bit
    let mut msg_vecs: [MsgVector; 256] = [MsgVector::from_element(false); 256];
    for i in 0..256 {
        let b2hash = blake2s_simd::blake2s(&ms[i]);
        let msg_vector = MsgVector::from_vec(bytes_to_bits(b2hash.as_bytes()));
        msg_vecs[i] = msg_vector;
    }
    // matrix of all leaked messages in bits, formed from row
    let matrix_ms = MsgsMatrix::from_rows(&msg_vecs);

    // 3. solve the system

    // 4. calculate signature
    // let sig;
    // for (s, a) in sigs.iter().zip(va.iter()) {
    //     if *a {
    //         sig += s;
    //     }
    // }

    // 5. verify
    // verify(pk, m, sig);

    /*************** (FAILED) APPROACH 2: ***************/
    // // pick a known message mk and the signature matching the known message sigk
    // // sigk = H(mk) * sk where sk is the secret key (unknown)
    // // take my message m
    // // let Hi(mk) be the multiplicative inverse of H(mk)
    // // calculate a valid signature for my message as:
    // sig = (H(m) * Hi(mk)) * sigk = (H(m) * Hi(mk)) * H(mk) * sk = H(m) * sk

    // // steps:
    // // 0. create my message
    // let m = hex::decode("grjte").unwrap();

    // // 1. get arbitrary mk & its signature from the leaked data
    // let mk = &ms[0];
    // let sigk = sigs[0];

    // // 2. get the hash of mk
    // let (_, hmk) = hash_to_curve(mk);

    // // 3. get the hash of m
    // let (_, hm) = hash_to_curve(&m);

    // // 4. create a signature for my message using the sigk
    // let sig = (hm / hmk) * sigk;

    // // verify
    // verify(pk, &m, sig);

    /*************** (FAILED) APPROACH 1: ***************/
    // // Find 2 leaked ms such that m1 ^ m2 = m, where m is my message
    // // If we can do this, then we will have H(m1) + H(m2) = H(m),
    // // which lets us construct a valid signature from the leaked signatures, since
    // // sig = H(m)[sk] = (H(m1) + H(m2))[sk] = H(m1)[sk] + H(m2)[sk] = sig1 + sig2

    // // 1. generate message m
    // let mut m: Vec<u8> = String::from("grjte").as_bytes().to_vec();
    // // pad m with zeros to size of 32 bytes
    // m.resize(32, 0);

    // // 2. choose any leaked message - this is arbitrary
    // let m1index = 1;
    // let m1 = &ms[m1index];

    // // 3. I want to find m2 such that m1 ^ m2 = m
    // // xor is its own inverse, so I can just do this: m ^ m1 = m2
    // // iterate over the vectors and xor each byte
    // let m2: Vec<u8> = m1.iter().zip(m.iter()).map(|(&x, &x1)| x ^ x1).collect();

    // // println!("m:{:?}", m);
    // // println!("m1:{:?}", m1);
    // // println!("m2:{:?}", m2);

    // // 4. get the signature of m1
    // let sig1 = sigs[m1index];

    // // 5. find a message matching our computed m2
    // // the index of m2 will not be the same as the index, so we can use this as a starting condition to check against later when verifying we actually found m2
    // let mut index = m1index;
    // // println!("m2:{:?}", m2);
    // for i in 0..ms.len() {
    //     // println!("m{}:{:?}", i, ms[i]);
    //     if ms[i] == m2 {
    //         index = i;
    //         break;
    //     }
    // }

    // // make sure that we have actually found a matching message for m2 before continuing
    // // if we have succeeded, it will not be 0, because that is the index of our m1
    // // assert!(index != m1index && index <= ms.len());

    // // 6. get the signature of m2
    // let sig2 = sigs[index];

    // // 7. compute my signature sig = sig1 + sig2
    // let sig = sig1 + sig2;

    // verify(pk, &m, sig);

    /*************** APPROACH 0: sanity check of running a verification in Rust (aka Hello, Rust!) ***************/
    // verify one of the existing message + signature combinations
    // let sig = G1Affine::deserialize(&mut Cursor::new(hex::decode("067ffcb122c43181eb4c525d2a7b56714262aae808ae24b62aa5ec6e1035a9f6ce6473f19dc470957afa98b437c68814").unwrap())).unwrap();
    // let m =
    //     hex::decode("f7ec1334115b5fe74475f662d3d0190b4526b2bb5dcfb3e6f235f1e90f61d85a").unwrap();
    // verify(pk, &m, sig);
}
