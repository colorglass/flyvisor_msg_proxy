
use clap::Parser;
use gmssl::Sm4Key;
use std::{io, net::Ipv4Addr};

mod gmssl;
mod chiper_pkg;

/// transport for encrypted mavlink message
#[derive(Parser)]
struct CliArgs {
    
    /// input serial device port, device path in unix or com port in windows
    #[arg(value_name="serial_port")]
    serial_port: String,

    /// output udp ip address
    #[arg(short, long, default_value_t=Ipv4Addr::LOCALHOST, value_name="ip")]
    addr: Ipv4Addr,

    /// baudrate for input serial device
    #[arg(short, long, default_value_t=57600)]
    baudrate: u32,

    /// output udp port number
    #[arg(short, long, default_value_t=14550)]
    port: u16,

    /// enable debug infomations
    #[arg(short, long)]
    debug: bool,
    
}

struct SecureChannel<RW: io::Write + io::Read> {
    key: Sm4Key,
    port: RW,
    authed: bool,
}

impl<RW> SecureChannel<RW> 
    where RW: io::Write + io::Read {
        fn new(port: RW) -> Self {
            SecureChannel {
                key: Sm4Key::default(),
                port,
                authed: false,
            }
        }


        fn connect(&mut self) {
            let key = gmssl::sm2_make_keypair().unwrap();
            let ecdh_msg = gmssl::sm2_ecdh_make_msg(&key).unwrap();

            let request_pkg = chiper_pkg::make_package(chiper_pkg::PackageFun::RequestConn, ecdh_msg);
            chiper_pkg::send_package(&mut self.port, &request_pkg).unwrap();

            let response_pkg = chiper_pkg::recv_package(&mut self.port).unwrap();
            match response_pkg.fun {
                chiper_pkg::PackageFun::ResponseOk => {
                    println!("secure connection created");
                }
                chiper_pkg::PackageFun::ResponseErr => {
                    panic!("Connection failed with error: {:?}", response_pkg.message[0]);
                }
                _ => ()
            }

            let ecdh_shared = gmssl::sm2_ecdh_make_shared_secret(&key, &response_pkg.message).unwrap();
            self.key = gmssl::sm3_kdf(&ecdh_shared).unwrap();
        }


        fn auth(&mut self, id: &str, pem: &str, psk: &str) {
            let id = id.as_bytes();
            let id_hash = gmssl::sm3_digest(&id, id.len()).unwrap();

            // get the first 8 char of the hash
            let id_hash = id_hash[0..4].iter().map(|x| format!("{:x}", x)).collect::<String>();
            self.send(chiper_pkg::PackageFun::RequestAuth, &id_hash.into_bytes());

            let (encrypted_random, fun) = self.recv();
            if fun != chiper_pkg::PackageFun::ResponseOk {
                panic!("Authentication 0 failed, fun: {:?}, msg: {:?}", fun, encrypted_random);
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
                panic!("Authentication 1 failed, fun: {:?}, msg: {:?}", fun, response);
            }
        }


        fn reset(&mut self) {
            self.key = Sm4Key::default();
            self.authed = false;
        }


        fn send(&mut self, fun: chiper_pkg::PackageFun, data: &Vec<u8>) {
            if self.key == Sm4Key::default() {
                panic!("Connection not established");
            }

            if fun == chiper_pkg::PackageFun::Data {

            }

            let msg = gmssl::sm4_cbc_padding_encrypt(&self.key, data).unwrap();
            let pkg = chiper_pkg::make_package(fun, msg);
            chiper_pkg::send_package(&mut self.port, &pkg).unwrap();
        }


        fn recv(&mut self) -> (Vec<u8>, chiper_pkg::PackageFun) {
            if self.key == Sm4Key::default() {
                panic!("Connection not established");
            }

            let pkg = chiper_pkg::recv_package(&mut self.port).unwrap();

            let msg: Vec<u8>;
            if pkg.fun == chiper_pkg::PackageFun::ResponseErr {
                msg = pkg.message;
            } else {
                msg = gmssl::sm4_cbc_padding_decrypt(&self.key, &pkg.message).unwrap();
            }

            (msg, pkg.fun)
        }
}

fn main() {

    let args = CliArgs::parse();

    let mut serialport = serialport::new(args.serial_port, args.baudrate)
        .open()
        .expect("Failed to open serial port");
    serialport.set_timeout(std::time::Duration::from_secs(100))
        .expect("Failed to set serial port timeout");


    
    let mut channel = SecureChannel::new(serialport);
    channel.connect();
    channel.auth("test_psk_public_key", "private_key.pem", "test_psk");


}