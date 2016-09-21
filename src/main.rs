extern crate fastcgi;
extern crate crypto;
extern crate rustc_serialize;

use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha1::Sha1;

use std::net::TcpListener;
use std::io::{Read, Write};

use rustc_serialize::hex::FromHex;

use fastcgi::Request;

use std::env;

macro_rules! try_option{
    ($operand:expr) => {
        if let Some(x) = $operand {
            x
        } else {
            return;
        }
    }
}
macro_rules! try_res{
    ($operand:expr) => {
        if let Ok(x) = $operand {
            x
        } else {
            return;
        }
    }
}


fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 4 {
        println!("Usage: {} port secret command command_arguments", args[0]);
        return;
    }
    let port = &args[1];
    let secret = &args[2];
    let script = &args[3..];
    let f = |req: Request| process_request(req, secret, script);
    fastcgi::run_tcp(f,
                     &TcpListener::bind(format!("127.0.0.1:{}", port).as_str()).unwrap());
}

fn process_request(mut request: Request, secret: &str, script: &[String]) {
    let github_event = try_option!(request.param("HTTP_X_GITHUB_EVENT"));
    let mut github_sig = try_option!(request.param("HTTP_X_HUB_SIGNATURE"));
    if github_sig.starts_with("sha1=") {
        github_sig = github_sig[5..].to_string();
    }
    let request_method = try_option!(request.param("REQUEST_METHOD"));
    if request_method != "POST" {
        return;
    }
    let mut buffer = String::new();
    try_res!(request.stdin().read_to_string(&mut buffer));
    if let Err(e) = github_sig.as_str().from_hex() {
        println!("{:?}", e);
    }
    let sig_bytes = try_res!(github_sig.as_str().from_hex());
    if validate(secret.as_bytes(), &sig_bytes, buffer.as_bytes()) {
        //    Valid message. Lets run script
        if let Err(e) = std::process::Command::new(&script[0]).args(&script[1..]).spawn() {
            println!("{:?}", e);
        }
        request.stdout().write(b"Content-Type: text/html; charset=utf-8\n\n");
    }
}

fn validate(secret: &[u8], signature: &[u8], message: &[u8]) -> bool {
    let mut hmac = Hmac::new(Sha1::new(), secret);
    hmac.input(&message[..]);
    hmac.result() == MacResult::new(&signature[..])
}
