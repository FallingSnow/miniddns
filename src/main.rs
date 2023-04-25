use hosts::UpdateStatus;
use log::{debug, error, info, warn};
use std::fs::File;
use std::io::{Error, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;
use std::{env, io};

#[cfg(feature = "auth")]
mod crypto;
mod hosts;

fn read_stream(stream: &mut TcpStream) -> io::Result<(String, String)> {
    let peer_addr = stream.peer_addr()?;
    debug!("New connection: {}", peer_addr);
    let mut data = [0 as u8; 1500];

    #[cfg(feature = "auth")]
    let secret = env::var("MINIDDNS_SECRET").unwrap();

    // We only attempt to read one packet before closing the stream
    stream
        .set_read_timeout(Some(Duration::from_millis(3)))
        .expect("Could not set a read timeout");
    match stream.read(&mut data) {
        Ok(size) => {
            let mut message = std::str::from_utf8(&data[..size]).map_err(|e| {
                Error::new(io::ErrorKind::Other, format!("Message decoding error: {e}"))
            })?;

            // Handle authenticating the message
            if message.starts_with("auth-") {
                #[cfg(feature = "auth")]
                {
                    message = crypto::validate_message(message, secret.as_bytes())?;
                }

                #[cfg(not(feature = "auth"))]
                {
                    let (_auth, no_auth_message) = message.split_once(' ').ok_or(Error::new(
                        io::ErrorKind::Other,
                        format!("Invalid message from {peer_addr}"),
                    ))?;
                    message = no_auth_message;
                }
            }
            let str = message.split_once(' ');

            let (mut ip, domains) = match str {
                Some((ip, domains)) => (ip.trim().to_owned(), domains.trim().to_owned()),
                None => {
                    return Err(Error::new(
                        io::ErrorKind::Other,
                        format!("Invalid message from {peer_addr}"),
                    ));
                }
            };

            // FIXME: This will catch valid domains too (Eg. localhost.domain.com)
            // You may not set localhost ips
            if domains.contains("localhost") {
                return Err(Error::new(
                    io::ErrorKind::Other,
                    format!("{peer_addr} attempted to set a localhost ip"),
                ));
            }

            // Ensure both ip and domains are not empty
            if domains.is_empty() || ip.is_empty() {
                return Err(Error::new(
                    io::ErrorKind::Other,
                    format!("{peer_addr} sent an invalid message"),
                ));
            }

            // Convert auto target_ip requests into the packet's IP address
            if ip == "auto" {
                ip = peer_addr.to_string();
            } else if env::var("MINIDDNS_FORCE_AUTO").is_ok() {
                return Err(Error::new(
                    io::ErrorKind::Other,
                    format!("{peer_addr} is did not send ip as \"auto\" as required"),
                ));
            }

            info!("Updating DNS entry [{domains} -> {ip}]");

            Ok((ip, domains))
        }
        Err(e) => return Err(e),
    }
}

fn process_stream(stream: &mut TcpStream, hosts_path: &Path) -> io::Result<UpdateStatus> {
    let (ip, domains) = read_stream(stream)?;
    let status = hosts::update_dns_entry(&domains, &ip, hosts_path)?;

    Ok(status)
}

fn main() {
    #[cfg(feature = "env_logger")]
    {
        // Set default log level to info if not already set
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "miniddnsd=info")
        }
        env_logger::init();
    }

    // Ensure we can read secret is auth is enabled
    #[cfg(feature = "auth")]
    env::var("MINIDDNS_SECRET").unwrap();

    let port = env::var("MINIDDNS_PORT")
        .map(|val| val.parse::<u16>().unwrap())
        .unwrap_or(5533);
    let address = env::var("MINIDDNS_ADDRESS").unwrap_or("0.0.0.0".to_string());

    let listener = TcpListener::bind((address, port)).unwrap();
    info!("Listening on {}", listener.local_addr().unwrap());

    let hosts = env::var("MINIDDNS_HOSTS_PATH").unwrap_or("/etc/hosts".to_string());
    let hosts_path = Path::new(&hosts);

    // Make sure we can open the file
    {
        File::options()
            .read(true)
            .write(true)
            .open(hosts_path)
            .expect("Failed to open hosts file");
    }

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let msg = match process_stream(&mut stream, &hosts_path) {
                    Ok(status) => {
                        format!("{status:?}")
                    }
                    Err(e) => {
                        warn!("{e}");
                        format!("{e}")
                    }
                };
                if let Err(e) = stream.write(msg.as_bytes()) {
                    warn!("Failed to write message to stream: {e}");
                }
                if let Err(e) = stream.shutdown(Shutdown::Both) {
                    warn!("Failed to shutdown stream: {e}");
                };
            }
            Err(e) => {
                error!("Stream Error: {e}");
            }
        }
    }
}
