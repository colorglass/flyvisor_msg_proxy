use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io;

const HEADER_MAGIC: u8 = 0xe7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageFun {
    RequestConn = 0x01,
    RequestAuth = 0x02,
    Data = 0x04,
    ResponseOk = 0x10,
    ResponseErr = 0x20,
}

#[derive(Debug)]
pub struct Package {
    magic: u8,
    pub fun: PackageFun,
    pub len: u16,
    pub message: Vec<u8>,
}

pub fn recv_package(reader: &mut impl io::Read) -> Result<Package, io::Error> {
    loop {
        if reader.read_u8()? == HEADER_MAGIC {
            break;
        }
    }

    let fun = match reader.read_u8()? {
        0x01 => PackageFun::RequestConn,
        0x02 => PackageFun::RequestAuth,
        0x04 => PackageFun::Data,
        0x10 => PackageFun::ResponseOk,
        0x20 => PackageFun::ResponseErr,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid package fun")),};

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
    writer.write_u8(package.fun as u8)?;
    writer.write_u16::<LittleEndian>(package.len)?;
    writer.write_all(&package.message)?;

    Ok(())
}

pub fn make_package(fun: PackageFun, message: Vec<u8>) -> Package {
    let len = message.len() as u16;
    Package {
        magic: HEADER_MAGIC,
        fun,
        len,
        message,
    }
}

