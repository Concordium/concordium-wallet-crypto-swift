use concordium_base::{ 
    web3id::v1::anchor::VerificationRequestData};
use wallet_library::proofs::{PresentationV1Input, VerificationRequestV1Input};

use crate::{ConcordiumWalletCryptoError, ConvertError, Bytes};

// #[uniffi::export]
pub fn create_presentation(input: String) -> Result<String, ConcordiumWalletCryptoError> {
    let fn_desc = "create_presentation(input={input})";
    let proof_input: PresentationV1Input =
        serde_json::from_str(&input).map_err(|e| e.to_call_failed(fn_desc.to_string()))?;

    // this must be returned
    let _presentation = match proof_input.prove() {
        Ok(val) => val,
        Err(_err) => todo!(),
    };

    Ok(String::new())
}

#[uniffi::export]
pub fn compute_anchor_hash(input: String) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "compute_anchor_hash(input={input})";
    let input: VerificationRequestV1Input =
        serde_json::from_str(&input).map_err(|e| e.to_call_failed(fn_desc.to_string()))?;

    let verification_request_data = VerificationRequestData {
        context: input.context,
        subject_claims: input.subject_claims,
    };

    let hash= verification_request_data.hash();

    Ok(hash.into())
}


