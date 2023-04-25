use std::{
    fs::File,
    io::{BufRead, BufReader, Error, Seek, Write},
    path::Path,
};

use log::trace;

const DELIMITER: u8 = b'\n';
// https://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
const DOMAIN_EXPRESSION: &'static str =
    r"^(([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$";
// https://stackoverflow.com/questions/23483855/javascript-regex-to-validate-ipv4-and-ipv6-address-no-hostnames
const IP_EXPRESSION: &'static str = r"((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))";

#[cfg(feature = "strict")]
lazy_static::lazy_static! {
    static ref DOMAIN_REGEX: regex::Regex = regex::Regex::new(DOMAIN_EXPRESSION).unwrap();
    static ref IP_REGEX: regex::Regex = regex::Regex::new(IP_EXPRESSION).unwrap();
}

#[derive(Debug)]
pub enum UpdateStatus {
    Created,
    Modified,
}

pub fn update_dns_entry(
    domains: &str,
    address: &str,
    file_path: &Path,
) -> std::io::Result<UpdateStatus> {
    let host_file = File::options().read(true).write(true).open(file_path)?;

    let mut reader = BufReader::new(host_file);
    let mut buf = Vec::new();
    let mut update_status = UpdateStatus::Created;

    // Read each line checking to see if it starts with ${address}
    reader.read_until(DELIMITER, &mut buf)?;
    while !buf.starts_with(address.as_bytes()) {
        // trace!("{}", std::str::from_utf8(&buf).unwrap());
        buf.clear();
        let bytes_read = reader.read_until(DELIMITER, &mut buf)?;
        if bytes_read == 0 {
            break;
        }
    }

    let matched = buf.len() != 0;
    let reader_pos = reader.stream_position()?;
    let pos = reader_pos - buf.len() as u64;
    // trace!("{}", std::str::from_utf8(&buf).unwrap());

    // Check if "64 bytes + \n" or "64 bytes without \n"
    let is_own_entry =
        buf.len() == 64 && buf[63] != DELIMITER || buf.len() == 65 && buf[64] == DELIMITER;

    if matched && !is_own_entry {
        return Err(Error::new(
            std::io::ErrorKind::Other,
            "Tried to modify entry not created by this program",
        ));
    }

    if matched {
        update_status = UpdateStatus::Modified;
    }

    let mut host_file = reader.into_inner();
    host_file.seek(std::io::SeekFrom::Start(pos))?;

    // Validate input data
    #[cfg(feature = "strict")]
    {
        for domain in domains.split(' ') {
            trace!("Testing domain regex: {domain}");
            if !DOMAIN_REGEX.is_match(domain) {
                return Err(Error::new(
                    std::io::ErrorKind::Other,
                    "invalid domains in message",
                ));
            }
        }

        trace!("Testing ip regex: {address}");
        if !IP_REGEX.is_match(address) {
            return Err(Error::new(
                std::io::ErrorKind::Other,
                "invalid ip address in message",
            ));
        }
    }

    let new_entry = format!("{address} {domains}");

    let padded_entry = if !matched {
        format!("\n{new_entry:64}")
    } else {
        format!("{new_entry:64}")
    };

    let entry_bytes = padded_entry.as_bytes();

    if entry_bytes.len() > 65 {
        return Err(Error::new(
            std::io::ErrorKind::Other,
            "new entry exceeds entry size limit",
        ));
    }

    host_file.write_all(entry_bytes)?;
    host_file.flush()?;

    Ok(update_status)
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    #[cfg_attr(feature = "env_logger", test_log::test)]
    #[cfg_attr(not(feature = "env_logger"), test)]
    fn add_one_host() {
        let mut file_path = env::temp_dir();
        file_path.push("add_one_host");
        fs::write(&file_path, "").unwrap();

        let result = super::update_dns_entry("newdomain.net", "192.168.254.253", &file_path);

        let output = fs::read_to_string(&file_path).unwrap();
        fs::remove_file(file_path).unwrap();

        result.unwrap();
        assert_eq!(output, format!("\n{:64}", "192.168.254.253 newdomain.net"));
    }

    #[cfg_attr(feature = "env_logger", test_log::test)]
    #[cfg_attr(not(feature = "env_logger"), test)]
    fn add_two_hosts() {
        let mut file_path = env::temp_dir();
        file_path.push("two_hosts");
        fs::write(
            &file_path,
            format!("\n{:64}", "192.168.254.253 olddomain.net"),
        )
        .unwrap();

        let result =
            super::update_dns_entry("newdomain.net olddomain.net", "192.168.254.220", &file_path);

        let output = fs::read_to_string(&file_path).unwrap();
        fs::remove_file(file_path).unwrap();

        result.unwrap();
        assert_eq!(
            output,
            format!(
                "\n{:64}\n{:64}",
                "192.168.254.253 olddomain.net", "192.168.254.220 newdomain.net olddomain.net"
            )
        );
    }

    #[cfg_attr(feature = "env_logger", test_log::test)]
    #[cfg_attr(not(feature = "env_logger"), test)]
    fn modify_existing() {
        let mut file_path = env::temp_dir();
        file_path.push("modify_existing");
        fs::write(
            &file_path,
            format!("\n{:64}", "192.168.254.253 olddomain.net"),
        )
        .unwrap();

        let result = super::update_dns_entry("newdomain.com", "192.168.254.253", &file_path);

        let output = fs::read_to_string(&file_path).unwrap();
        fs::remove_file(file_path).unwrap();

        result.unwrap();
        assert_eq!(output, format!("\n{:64}", "192.168.254.253 newdomain.com"));
    }
}
