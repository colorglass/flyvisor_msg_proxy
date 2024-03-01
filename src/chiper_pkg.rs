use std::{io::{self, Read}, ptr::read};
use serial2::SerialPort;

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

pub fn recv_package(port: &SerialPort) -> Result<Package, io::Error> {

    let mut buf = [0u8; 2];
    loop {
        port.read_exact(&mut buf[..1])?;
        if buf[0] == HEADER_MAGIC {
            break;
        }
    }

    port.read_exact(&mut buf[..1])?;
    let fun = match buf[0] {
        0x01 => PackageFun::RequestConn,
        0x02 => PackageFun::RequestAuth,
        0x04 => PackageFun::Data,
        0x10 => PackageFun::ResponseOk,
        0x20 => PackageFun::ResponseErr,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid package fun")),
    };

    port.read_exact(&mut buf)?;
    let len = u16::from_le_bytes(buf);

    let mut message = vec![0u8; len as usize];
    port.read_exact(&mut message)?;

    Ok(Package {
        magic: HEADER_MAGIC,
        fun,
        len,
        message,
    })
}

pub fn send_package(port: &SerialPort, package: &Package) -> Result<(), io::Error> {
    port.write_all(&[package.magic])?;
    port.write_all(&[package.fun as u8])?;
    port.write_all(&package.len.to_le_bytes())?;
    port.write_all(&package.message)?;

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

