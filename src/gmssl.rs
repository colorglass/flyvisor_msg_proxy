use libc;
use std::fmt;
use std::mem::size_of;

mod ffi;
pub use ffi::Sm2Point;

pub type Sm4Key = [u8; 32];

const BUFFER_SIZE: usize = 1024;

#[derive(Debug)]
pub struct SmError {
    pub msg: String,
}

impl SmError {
    pub fn new(msg: &str) -> SmError {
        SmError {
            msg: msg.to_string(),
        }
    }
}

impl fmt::Display for SmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SmError: {}", self.msg)
    }
}

impl std::error::Error for SmError {}

pub fn sm2_make_keypair() -> Result<ffi::Sm2KeyPair, SmError> {
    let mut my_key_pair = ffi::Sm2KeyPair::default();
    unsafe {
        if ffi::sm2_key_generate(&mut my_key_pair) == 0 {
            return Err(SmError::new("sm2_key_generate failed"));
        }
    }
    Ok(my_key_pair)
}

pub fn sm2_ecdh_make_msg(key: &ffi::Sm2KeyPair) -> Result<Vec<u8>, SmError> {
    let mut octets = Box::new([0u8; 65]);
    unsafe {
        ffi::sm2_point_to_uncompressed_octets(&key.pub_key, &mut *octets as *mut u8);
    }

    Ok(octets.to_vec())
}

pub fn sm2_ecdh_make_shared_secret(
    key: &ffi::Sm2KeyPair,
    peer_hub: &[u8],
) -> Result<Sm2Point, SmError> {
    let mut shared_secret = ffi::Sm2Point::default();
    unsafe {
        if ffi::sm2_ecdh(key, peer_hub.as_ptr(), peer_hub.len(), &mut shared_secret) == 0 {
            return Err(SmError::new("sm2_ecdh failed"));
        }
    }

    Ok(shared_secret)
}

pub fn sm2_decrypt(key: &ffi::Sm2KeyPair, indata: &[u8]) -> Result<Vec<u8>, SmError> {
    let mut outdata = vec![0u8; BUFFER_SIZE];
    let mut outlen = 0;
    unsafe {
        if ffi::sm2_decrypt(
            key,
            indata.as_ptr(),
            indata.len(),
            outdata.as_mut_ptr(),
            &mut outlen,
        ) == -1
        {
            return Err(SmError::new("sm2_decrypt failed"));
        }
    }
    if outlen > BUFFER_SIZE {
        return Err(SmError::new("sm2_decrypt failed: outlen > BUFFER_SIZE"));
    }
    outdata.truncate(outlen);
    Ok(outdata)
}

pub fn sm2_priv_key_from_pem(file_path: &str, password: &str) -> Result<ffi::Sm2KeyPair, SmError> {
    let mut key = ffi::Sm2KeyPair::default();
    let file_path = std::ffi::CString::new(file_path).unwrap();
    let mode = std::ffi::CString::new("r").unwrap();
    let password = std::ffi::CString::new(password).unwrap();

    let file = unsafe { libc::fopen(file_path.as_ptr(), mode.as_ptr()) };

    if file.is_null() {
        return Err(SmError::new("fopen failed"));
    }

    unsafe {
        if ffi::sm2_private_key_info_decrypt_from_pem(&mut key, password.as_ptr(), file) == -1 {
            return Err(SmError::new("sm2_private_key_info_decrypt_from_pem failed"));
        }
    }
    Ok(key)
}

pub fn sm3_digest(data: &[u8], datalen: usize) -> Result<Vec<u8>, SmError> {
    let mut digest = vec![0u8; 32];
    unsafe {
        ffi::sm3_digest(data.as_ptr(), datalen, digest.as_mut_ptr());
    }
    Ok(digest)
}

pub fn sm3_kdf(ecdh_shared: &Sm2Point) -> Result<Sm4Key, SmError> {
    let mut ctx = ffi::Sm3KdfCtx::default();
    let outlen = 32;
    let p = ecdh_shared as *const Sm2Point as *const u8;
    unsafe {
        ffi::sm3_kdf_init(&mut ctx, outlen);
        ffi::sm3_kdf_update(&mut ctx, p, size_of::<Sm2Point>());
    }
    let mut out = vec![0u8; outlen];
    unsafe {
        ffi::sm3_kdf_finish(&mut ctx, out.as_mut_ptr());
    }
    Ok(out.try_into().unwrap())
}

pub fn sm4_cbc_padding_decrypt(key: &Sm4Key, indata: &[u8]) -> Result<Vec<u8>, SmError> {

    if indata.len() == 0 {
        return Ok(Vec::new());
    }

    let mut sm4_decrypt_key = ffi::Sm4Key::default();
    let raw_key = key[0..16].as_ptr();
    let iv = key[16..32].as_ptr();
    let mut outdata = vec![0u8; BUFFER_SIZE];
    let mut outlen = 0;
    unsafe {
        ffi::sm4_set_decrypt_key(&mut sm4_decrypt_key, raw_key);
        if ffi::sm4_cbc_padding_decrypt(
            &sm4_decrypt_key,
            iv,
            indata.as_ptr(),
            indata.len(),
            outdata.as_mut_ptr(),
            &mut outlen,
        ) == -1
        {
            return Err(SmError::new("sm4_cbc_padding_decrypt failed"));
        }
    }
    if outlen > BUFFER_SIZE {
        return Err(SmError::new("sm2_decrypt failed: outlen > BUFFER_SIZE"));
    }
    outdata.truncate(outlen);
    Ok(outdata)
}

pub fn sm4_cbc_padding_encrypt(key: &Sm4Key, indata: &[u8]) -> Result<Vec<u8>, SmError> {

    if indata.len() == 0 {
        return Ok(Vec::new());
    }

    let mut sm4_encrypt_key = ffi::Sm4Key::default();
    let raw_key = key[0..16].as_ptr();
    let iv = key[16..32].as_ptr();
    let mut outdata = vec![0u8; BUFFER_SIZE];
    let mut outlen = 0;

    unsafe {
        ffi::sm4_set_encrypt_key(&mut sm4_encrypt_key, raw_key);
        if ffi::sm4_cbc_padding_encrypt(
            &sm4_encrypt_key,
            iv,
            indata.as_ptr(),
            indata.len(),
            outdata.as_mut_ptr(),
            &mut outlen,
        ) == -1
        {
            return Err(SmError::new("sm4_cbc_padding_encrypt failed"));
        }
    }
    if outlen > BUFFER_SIZE {
        return Err(SmError::new("sm2_decrypt failed: outlen > BUFFER_SIZE"));
    }
    outdata.truncate(outlen);
    Ok(outdata)
}
