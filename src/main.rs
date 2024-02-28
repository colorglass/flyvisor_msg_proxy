use clap::Parser;
use std::{io::Read, net::Ipv4Addr};

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

fn main() {

    let args = CliArgs::parse();

    let mut serialport = serialport::new(args.serial_port, args.baudrate)
        .open()
        .expect("Failed to open serial port");
    serialport.set_timeout(std::time::Duration::from_secs(100))
        .expect("Failed to set serial port timeout");

    let key = gmssl::sm2_make_keypair().unwrap();
    let message = gmssl::sm2_ecdh_make_msg(&key).unwrap();

    let request_pkg = chiper_pkg::make_package(chiper_pkg::FUN_REQUEST_CONN, message);
    chiper_pkg::send_package(&mut serialport, &request_pkg).unwrap();
    let response_pkg = chiper_pkg::recv_package(&mut serialport).unwrap();
    if response_pkg.fun == chiper_pkg::FUN_RESPONSE_OK {
        println!("Connection established");
        let ecdh_shared = gmssl::sm2_ecdh_make_shared_secret(&key, &response_pkg.message).unwrap();
        let sm4_key = gmssl::sm3_kdf(&ecdh_shared).unwrap();

        let id = b"test_psk_public_key";
        let id_hash = gmssl::sm3_digest(id, id.len()).unwrap();
        let id_hash = id_hash[0..4].iter().map(|x| format!("{:x}", x)).collect::<String>();
        println!("ID hash: {}", id_hash);

        let msg = gmssl::sm4_cbc_padding_encrypt(&sm4_key, id_hash.as_bytes()).unwrap();

        let request_pkg = chiper_pkg::make_package(chiper_pkg::FUN_REQUEST_AUTH, msg);
        chiper_pkg::send_package(&mut serialport, &request_pkg).unwrap();

        let response_pkg = chiper_pkg::recv_package(&mut serialport).unwrap();
        if response_pkg.fun == chiper_pkg::FUN_RESPONSE_ERR {
            println!("Authentication failed");
            return;
        }
        let resp0 = gmssl::sm4_cbc_padding_decrypt(&sm4_key, &response_pkg.message).unwrap();

        let sm2_key = gmssl::sm2_priv_key_from_pem("private_key.pem", "test_psk").unwrap();
        let mut random_num = gmssl::sm2_decrypt(&sm2_key, &resp0).unwrap();
        random_num.append(&mut Vec::from(sm4_key));

        let rst = gmssl::sm3_digest(&random_num, random_num.len()).unwrap();
        let msg = gmssl::sm4_cbc_padding_encrypt(&sm4_key, &rst).unwrap();
        let request_pkg = chiper_pkg::make_package(chiper_pkg::FUN_REQUEST_AUTH, msg);
        chiper_pkg::send_package(&mut serialport, &request_pkg).unwrap();
        let response_pkg = chiper_pkg::recv_package(&mut serialport).unwrap();
        if response_pkg.fun == chiper_pkg::FUN_RESPONSE_OK {
            println!("Authentication success");
        } else {
            println!("Authentication failed");
        }
    } else {
        println!("Connection failed");
    }

}