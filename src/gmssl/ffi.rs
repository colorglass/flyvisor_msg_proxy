use libc;
use serde::Serialize;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Serialize)]
pub struct Sm2Point {
    x: [u8; 32],
    y: [u8; 32],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Sm2KeyPair {
    pub pub_key: Sm2Point,
    priv_key: [u8; 32],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
struct Sm3Ctx {
    digest: [u32; 8],
    nblocks: u64,
    block: [u64; 8],
    num: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Sm3KdfCtx {
    sm3_ctx: Sm3Ctx,
    outlen: usize
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Sm4Key {
    rk: [u32; 32],
}

#[link(name = "gmssl", kind = "dylib")]
extern "C" {
    pub fn sm2_key_generate(key: *mut Sm2KeyPair) -> libc::c_int;
    pub fn sm2_decrypt(key: *const Sm2KeyPair, indata: *const u8, inlen: usize, outdata: *mut u8, outlen: *mut usize) -> libc::c_int;
    pub fn sm2_point_to_uncompressed_octets(point: *const Sm2Point, out: *mut u8) -> libc::c_void;
    pub fn sm2_private_key_info_decrypt_from_pem(
        key: *mut Sm2KeyPair,
        password: *const libc::c_char,
        fp: *mut libc::FILE,
    ) -> libc::c_int;
    pub fn sm2_ecdh(key: *const Sm2KeyPair, peer_pub: *const u8, peer_pub_len: libc::size_t, out: *mut Sm2Point) -> libc::c_int;
    pub fn sm3_digest(data: *const u8, datalen: usize, digest: *mut u8) -> libc::c_void;
    pub fn sm3_kdf_init(ctx: *mut Sm3KdfCtx, outlen: usize) -> libc::c_void;
    pub fn sm3_kdf_update(ctx: *mut Sm3KdfCtx, indata: *const u8, inlen: usize) -> libc::c_void;
    pub fn sm3_kdf_finish(ctx: *mut Sm3KdfCtx, out: *mut u8) -> libc::c_void;
    pub fn sm4_set_encrypt_key(key: *mut Sm4Key, rawkey: *const u8) -> libc::c_void;
    pub fn sm4_set_decrypt_key(key: *mut Sm4Key, rawkey: *const u8) -> libc::c_void;
    pub fn sm4_cbc_padding_encrypt(key: *const Sm4Key, iv: *const u8, 
        indata: *const u8, inlen: usize, outdata: *mut u8, outlen: *mut usize) -> libc::c_int;
    pub fn sm4_cbc_padding_decrypt(key: *const Sm4Key, iv: *const u8,
        indata: *const u8, inlen: usize, outdata: *mut u8, outlen: *mut usize) -> libc::c_int;
}