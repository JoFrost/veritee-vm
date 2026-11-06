use anyhow::{bail, Context as AnyhowContext};
use fn_error_context::context;
use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{
    Attest, CreatePrimaryKeyResult, Data, Digest, PcrSelectionList, PcrSelectionListBuilder,
    PcrSlot, Public, PublicKeyRsa, PublicRsaParameters, RsaDecryptionScheme, RsaExponent,
    SignatureScheme, SymmetricDefinition,
};

use tss_esapi::{interface_types::session_handles::AuthSession, Context};

use crate::tpm::VTPM_AK_HANDLE;

const VTPM_QUOTE_PCR_SLOTS: [PcrSlot; 24] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
    PcrSlot::Slot10,
    PcrSlot::Slot11,
    PcrSlot::Slot12,
    PcrSlot::Slot13,
    PcrSlot::Slot14,
    PcrSlot::Slot15,
    PcrSlot::Slot16,
    PcrSlot::Slot17,
    PcrSlot::Slot18,
    PcrSlot::Slot19,
    PcrSlot::Slot20,
    PcrSlot::Slot21,
    PcrSlot::Slot22,
    PcrSlot::Slot23,
];

#[context("Failed to create_ephemeral_key")]
pub fn create_ephemeral_key(
    ctx: &mut tss_esapi::Context,
    pcr_digest: &tss_esapi::structures::Digest,
    pcr_selection: &tss_esapi::structures::PcrSelectionList,
) -> Result<
    (
        CreatePrimaryKeyResult,
        Attest,
        tss_esapi::structures::Signature,
    ),
    anyhow::Error,
> {
    use tss_esapi::interface_types::resource_handles::Hierarchy;
    let obj_attributes = ObjectAttributes::builder()
        .with_decrypt(true)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_no_da(true)
        .build()?;

    let rsa_params = PublicRsaParameters::builder()
        .with_scheme(tss_esapi::structures::RsaScheme::Null)
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::ZERO_EXPONENT)
        .build()?;
    // Set the alg to TPM2_ALG_NULL so the caller can specify the alg such as TPM2_ALG_OAEP or TPM2_ALG_RSAES
    // .with_scheme(Null)

    let auth_policy = get_ephemeral_key_policy_digest(ctx, pcr_digest, pcr_selection)?;
    // .with_symmetric(S)

    //println!("begin public template");
    let public_template = Public::builder()
        .with_object_attributes(obj_attributes)
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .with_rsa_parameters(rsa_params)
        .with_auth_policy(auth_policy)
        .build()?;
    //println!("end public template");

    // ctx
    let primary_creation_res = ctx.execute_with_nullauth_session(|ctx| {
        anyhow::Ok(
            ctx.create_primary(Hierarchy::Null, public_template, None, None, None, None)
                .context("Failed to create Ephemeral Key")?,
        )
    })?;

    let obj_handle = ctx.tr_from_tpm_public(VTPM_AK_HANDLE.try_into()?)?;
    // Certify
    let (attest, sig) = ctx.execute_with_sessions(
        (
            Some(AuthSession::Password),
            Some(AuthSession::Password),
            None,
        ),
        |ctx| {
            ctx.certify(
                primary_creation_res.key_handle.into(),
                obj_handle.into(),
                Data::default(),
                SignatureScheme::Null,
            )
        },
    )?;
    Ok((primary_creation_res, attest, sig))
}

#[context("Failed to get_ephemeral_key_policy_digest")]
fn get_ephemeral_key_policy_digest(
    ctx: &mut Context,
    pcr_digest: &tss_esapi::structures::Digest,
    pcr_selection: &tss_esapi::structures::PcrSelectionList,
) -> anyhow::Result<Digest> {
    //println!("begin");
    let auth_session = ctx
        .start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Trial,
            SymmetricDefinition::Null,
            HashingAlgorithm::Sha256,
        )?
        .context("Empty Session")?;

    //println!("end");

    let AuthSession::PolicySession(session) = auth_session else {
        bail!("Bad session type");
    };

    let _selection_list: tss_esapi::structures::PcrSelectionList = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &VTPM_QUOTE_PCR_SLOTS)
        .build()?;

    ctx.policy_pcr(session, pcr_digest.clone(), pcr_selection.clone())?;
    Ok(ctx.policy_get_digest(session)?)
}

pub(crate) fn decrypt_inner_key(
    ctx: &mut tss_esapi::Context,
    encrypted_inner_key: &[u8],
    key_handle: &KeyHandle,
    pcr_digest: &Digest,
    pcr_selection: &PcrSelectionList,
) -> anyhow::Result<Vec<u8>> {
    let auth_session = ctx
        .start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Policy,
            SymmetricDefinition::Null,
            HashingAlgorithm::Sha256,
        )?
        .context("Empty Session")?;

    ctx.policy_pcr(
        auth_session.try_into()?,
        pcr_digest.clone(),
        pcr_selection.clone(),
    )?;

    ctx.set_sessions((Some(auth_session), None, None));
    let ret_rsa_decrypt = ctx.rsa_decrypt(
        key_handle.clone(),
        PublicKeyRsa::try_from(encrypted_inner_key)?,
        RsaDecryptionScheme::RsaEs,
        Data::default(),
    )?;
    Ok(ret_rsa_decrypt.to_vec())
}
