use hosts::UpdateStatus;
use log::{debug, error, info, warn};
use std::io::{Error, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

#[cfg(feature = "auth")]
mod crypto;
mod hosts;

fn read_stream(stream: &mut TcpStream, secret: &[u8]) -> std::io::Result<UpdateStatus> {
    let peer_addr = stream.peer_addr()?;
    debug!("New connection: {}", peer_addr);
    let mut data = [0 as u8; 1500];

    // We only attempt to read one packet before closing the stream
    stream.set_read_timeout(Some(Duration::from_millis(3))).expect("Could not set a read timeout");
    match stream.read(&mut data) {
        Ok(size) => {
            let mut message = std::str::from_utf8(&data[..size]).unwrap();

            // Handle authenticating the message
            if message.starts_with("auth-") {
                // FIXME: Remove auth data from message if auth feature is not enabled
                #[cfg(feature = "auth")]
                {
                    message = crypto::validate_message(message, secret)?;
                }
            }
            let str = message.split_once(' ');

            let (ip, domains) = match str {
                Some((ip, domains)) => (ip.trim(), domains.trim()),
                None => {
                    stream.shutdown(Shutdown::Both)?;
                    return Err(Error::new(
                        std::io::ErrorKind::Other,
                        format!("Invalid message from {peer_addr}"),
                    ));
                }
            };

            // FIXME: This will catch valid domains too (Eg. localhost.domain.com)
            // You may not set localhost ips
            if domains.contains("localhost") {
                stream.shutdown(Shutdown::Both)?;
                return Err(Error::new(
                    std::io::ErrorKind::Other,
                    format!("{peer_addr} attempted to set a localhost ip"),
                ));
            }

            // Ensure both ip and domains are not empty
            if domains.is_empty() || ip.is_empty() {
                stream.shutdown(Shutdown::Both)?;
                return Err(Error::new(
                    std::io::ErrorKind::Other,
                    format!("{peer_addr} sent an invalid message"),
                ));
            }

            debug!("Updating DNS entry [{domains} -> {ip}]");

            hosts::update_dns_entry(&domains, ip, Path::new("/tmp/hosts"))
        }
        Err(e) => return Err(e),
    }
}

fn main() {
    #[cfg(feature = "env_logger")]
    env_logger::init();

    let port = std::env::var("MINIDDNS_PORT").map(|val| val.parse::<u16>().unwrap()).unwrap_or(5533);
    let address = std::env::var("MINIDDNS_ADDRESS").unwrap_or("0.0.0.0".to_string());

    let listener = TcpListener::bind((address, port)).unwrap();
    info!("Listening on {}", listener.local_addr().unwrap());

    #[cfg(feature = "auth")]
    let secret = std::env::var("MINIDDNS_SECRET").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let msg = match read_stream(&mut stream, secret.as_bytes()) {
                    Ok(status) => {
                        format!("{status:?}")
                    },
                    Err(e) => {
                        warn!("{e}");
                        format!("{e}")
                    },
                };
                stream.write(msg.as_bytes()).unwrap();
                stream.shutdown(Shutdown::Both).unwrap();
            }
            Err(e) => {
                error!("Error: {}", e);
            }
        }
    }
}
