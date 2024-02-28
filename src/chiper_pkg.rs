use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::io;

const HEADER_MAGIC: u8 = 0xe7;

pub const FUN_REQUEST_CONN: u8 = 0x01;
pub const FUN_REQUEST_AUTH: u8 = 0x02;
pub const FUN_DATA: u8 = 0x04;
pub const FUN_RESPONSE_OK: u8 = 0x10;
pub const FUN_RESPONSE_ERR: u8 = 0x20;

const ERROR_FUN: u8 = 0x01;
const ERROR_AUTH: u8 = 0x02;
const ERROR_CONN: u8 = 0x04;
const ERROR_PARAM: u8 = 0x08;
const ERROR_PUBKEY: u8 = 0x10;

#[derive(Debug, Serialize, Deserialize)]
pub struct Package {
    magic: u8,
    pub fun: u8,
    pub len: u16,
    pub message: Vec<u8>,
}

pub fn recv_package(reader: &mut impl io::Read) -> Result<Package, io::Error> {
    loop {
        if reader.read_u8()? == HEADER_MAGIC {
            break;
        }
    }

    let fun = reader.read_u8()?;
    let len = reader.read_u16::<LittleEndian>()?;
    let mut message = vec![0u8; len as usize];
    reader.read_exact(&mut message)?;

    Ok(Package {
        magic: HEADER_MAGIC,
        fun,
        len,
        message,
    })
}

pub fn send_package(writer: &mut impl io::Write, package: &Package) -> Result<(), io::Error> {
    writer.write_u8(package.magic)?;
    writer.write_u8(package.fun)?;
    writer.write_u16::<LittleEndian>(package.len)?;
    writer.write_all(&package.message)?;

    Ok(())
}

pub fn make_package(fun: u8, message: Vec<u8>) -> Package {
    let len = message.len() as u16;
    Package {
        magic: HEADER_MAGIC,
        fun,
        len,
        message,
    }
}

