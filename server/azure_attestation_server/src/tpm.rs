use tss_esapi::{
    abstraction::nv,
    handles::TpmHandle,
    interface_types::{
        resource_handles::NvAuth,
        session_handles::AuthSession, // PolicySession},
    },
    structures::PublicBuffer,
    tcti_ldr::DeviceConfig,
    traits::Marshall,
    Context, TctiNameConf,
};

use std::convert::{TryFrom, TryInto};

pub const VTPM_AK_HANDLE: u32 = 0x81000003;
pub const VTPM_AK_CERT_NV_INDEX: u32 = 0x01C101D0;

/// Get the AK pub of the vTPM
pub fn get_ak_pub() -> anyhow::Result<Vec<u8>> {
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;
    let (pk, _, _) = context.read_public(key_handle.into())?;
    let public_buffer = PublicBuffer::try_from(pk)?;
    Ok(public_buffer.marshall()?)
}

#[test]
fn test_get_ak_pub() {
    get_ak_pub().unwrap();
}

pub fn get_ak_cert() -> anyhow::Result<Vec<u8>> {
    use tss_esapi::handles::NvIndexTpmHandle;
    let nv_index = NvIndexTpmHandle::new(VTPM_AK_CERT_NV_INDEX)?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    let ak_cert = nv::read_full(&mut context, NvAuth::Owner, nv_index)?;
    Ok(ak_cert)
}

#[test]
fn test_get_ak_cert() {
    get_ak_cert().unwrap();
}
