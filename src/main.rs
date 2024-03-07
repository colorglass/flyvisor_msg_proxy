use std::{sync::Arc, time::Duration};

use clap::Parser;
use gmssl::Sm4Key;
use mavlink::{ardupilotmega, Message};
use serial2::SerialPort;
use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    thread,
};

mod chiper_pkg;
mod gmssl;

/// transport for encrypted mavlink message
#[derive(Parser)]
struct CliArgs {
    /// input serial device port, device path in unix or com port in windows
    #[arg(value_name = "serial_port")]
    serial_port: String,

    /// target udp ip address
    #[arg(short, long, default_value_t=Ipv4Addr::LOCALHOST, value_name="ip")]
    addr: Ipv4Addr,

    /// baudrate for input serial device
    #[arg(short, long, default_value_t = 57600)]
    baudrate: u32,

    /// target udp port number
    #[arg(short, long, default_value_t = 14550)]
    port: u16,

    /// enable debug infomations
    #[arg(short, long)]
    debug: bool,
}

// Abstract communication channel used to
struct SecureChannel {
    key: Sm4Key,
    port: SerialPort,
    authed: bool,
}

impl SecureChannel {
    fn new(port: SerialPort) -> Self {
        SecureChannel {
            key: Sm4Key::default(),
            port,
            authed: false,
        }
    }

    fn connect(mut self) -> Self {
        let key = gmssl::sm2_make_keypair().unwrap();
        let ecdh_msg = gmssl::sm2_ecdh_make_msg(&key).unwrap();

        let request_pkg = chiper_pkg::make_package(chiper_pkg::PackageFun::RequestConn, ecdh_msg);
        chiper_pkg::send_package(&self.port, &request_pkg).unwrap();

        let response_pkg = chiper_pkg::recv_package(&self.port).unwrap();
        match response_pkg.fun {
            chiper_pkg::PackageFun::ResponseOk => {
                println!("secure connection created");
            }
            chiper_pkg::PackageFun::ResponseErr => {
                panic!(
                    "Connection failed with error: {:?}",
                    response_pkg.message[0]
                );
            }
            _ => (),
        }

        let ecdh_shared = gmssl::sm2_ecdh_make_shared_secret(&key, &response_pkg.message).unwrap();
        self.key = gmssl::sm3_kdf(&ecdh_shared).unwrap();
        self
    }

    fn auth(mut self, id: &str, pem: &str, psk: &str) -> Self {
        let id = id.as_bytes();
        let id_hash = gmssl::sm3_digest(&id, id.len()).unwrap();

        // get the first 8 char of the hash
        let id_hash = id_hash[0..4]
            .iter()
            .map(|x| format!("{:x}", x))
            .collect::<String>();
        self.send(chiper_pkg::PackageFun::RequestAuth, &id_hash.into_bytes());

        let (encrypted_random, fun) = self.recv();
        if fun != chiper_pkg::PackageFun::ResponseOk {
            panic!(
                "Authentication 0 failed, fun: {:?}, msg: {:?}",
                fun, encrypted_random
            );
        }

        let sm2_key = gmssl::sm2_priv_key_from_pem(pem, psk).unwrap();
        let mut random = gmssl::sm2_decrypt(&sm2_key, &encrypted_random).unwrap();
        random.append(&mut Vec::from(self.key));
        let msg = gmssl::sm3_digest(&random, random.len()).unwrap();

        self.send(chiper_pkg::PackageFun::RequestAuth, &msg);
        let (response, fun) = self.recv();
        if fun == chiper_pkg::PackageFun::ResponseOk {
            self.authed = true;
            println!("Authentication success");
        } else {
            panic!(
                "Authentication 1 failed, fun: {:?}, msg: {:?}",
                fun, response
            );
        }
        self
    }

    #[allow(dead_code)]
    fn reset(&mut self) {
        self.key = Sm4Key::default();
        self.authed = false;
    }

    fn send(&self, fun: chiper_pkg::PackageFun, data: &[u8]) {
        if self.key == Sm4Key::default() {
            panic!("Connection not established");
        }

        if fun == chiper_pkg::PackageFun::Data {}

        let msg = gmssl::sm4_cbc_padding_encrypt(&self.key, data).unwrap_or_else(|e| {
            println!("encrypt error: {:?}", e);
            Vec::default()
        });
        let pkg = chiper_pkg::make_package(fun, msg);
        chiper_pkg::send_package(&self.port, &pkg).unwrap();
    }

    fn recv(&self) -> (Vec<u8>, chiper_pkg::PackageFun) {
        if self.key == Sm4Key::default() {
            panic!("Connection not established");
        }

        let pkg = chiper_pkg::recv_package(&self.port).unwrap();

        let msg: Vec<u8>;
        if pkg.fun == chiper_pkg::PackageFun::ResponseErr {
            msg = pkg.message;
        } else {
            msg = gmssl::sm4_cbc_padding_decrypt(&self.key, &pkg.message).unwrap_or_else(|e| {
                println!("encrypt error: {:?}", e);
                Vec::default()
            });
        }

        (msg, pkg.fun)
    }
}

#[allow(unused)]
fn trans_without_encrypt(serialport: SerialPort) {
    let serialport_0 = Arc::new(serialport);
    let serialport_1 = Arc::clone(&serialport_0);
    let udp_0 = Arc::new(UdpSocket::bind("0.0.0.0:0").unwrap());
    let udp_1 = Arc::clone(&udp_0);

    let thread1 = thread::spawn(move || {
        let mut buf = vec![0u8; 1024];
        loop {
            let (size, addr) = udp_0.recv_from(&mut buf).unwrap();
            println!("recived {} bytes from {}", size, addr);
            serialport_0.write_all(&buf).unwrap();
        }
    });

    let thread2 = thread::spawn(move || {
        let mut buf = vec![0u8; 1024];
        loop {
            let size = serialport_1.read(&mut buf).unwrap();
            println!("recived {} bytes from serial", size);
            let rst = udp_1
                .send_to(
                    &buf[..size],
                    SocketAddrV4::new("172.16.22.86".parse().unwrap(), 24550),
                )
                .unwrap();
            println!("send to: {:?}", rst);
        }
    });

    thread1.join().unwrap();
    thread2.join().unwrap();
}

fn main() {
    let args = CliArgs::parse();

    let mut serialport = SerialPort::open(args.serial_port, args.baudrate).unwrap();
    serialport.set_read_timeout(Duration::MAX).unwrap();

    // trans_without_encrypt(serialport);

    let udp = Arc::new(UdpSocket::bind("0.0.0.0:0").unwrap());
    let channel = Arc::new(SecureChannel::new(serialport).connect().auth(
        "test_psk_public_key",
        "private_key.pem",
        "test_psk",
    ));

    let channel_0 = Arc::clone(&channel);
    let udp_0 = Arc::clone(&udp);

    thread::spawn(move || {
        let mut buf = vec![0u8; 1024];
        loop {
            let (size, addr) = udp.recv_from(&mut buf).unwrap();
            let (_, msg): (_, ardupilotmega::MavMessage) =
                mavlink::read_v2_msg(&mut &buf[..]).unwrap();
            println!("recived msg: {} from {}", msg.message_name(), addr);

            channel.send(chiper_pkg::PackageFun::Data, &buf[..size]);
        }
    });

    loop {
        let (data, fun) = channel_0.recv();
        if fun == chiper_pkg::PackageFun::Data {
            if let Ok((header, msg)) =
                mavlink::read_v2_msg::<ardupilotmega::MavMessage, &[u8]>(&mut &data[..])
            {
                println!("recived msg: {} from remote", msg.message_name());
                let mut raw_msg = mavlink::MAVLinkV2MessageRaw::new();
                raw_msg.serialize_message(header, &msg);
                let _rst = udp_0
                    .send_to(raw_msg.raw_bytes(), SocketAddrV4::new(args.addr, args.port))
                    .unwrap();
            } else {
                continue;
            }
        } else {
            println!("fun: {:?}, data: {:?}", fun, data);
        }
    }
}
