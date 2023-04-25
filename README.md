## Compile
Make sure you have rust and cargo installed.
```
cargo run build --release
ls target/release/miniddnsd
```

## Usage
### Server
```
export MINIDDNS_SECRET=`tr -dc 'A-Za-z0-9' </dev/urandom | head -c 128`
miniddnsd
```

#### Server Environmental Variables
* `MINIDDNS_SECRET` - Define the secret used to authenticate tcp packets. This should be stored on the server and clients. This has no default and must be defined.
* `MINIDDNS_ADDRESS` - Define the ip address you would like to bind to. Defaults to `0.0.0.0` (all interfaces).
* `MINIDDNS_PORT` - Define the port to listen on. Defaults to `5533`.

### Client
miniddns is just a shell script that sends a tcp message. The `MINIDDNS_SECRET` must be the same used on the server above.
```
miniddns <ddns_host> <ddns_port> <secret> <target_domains> <target_ip>
miniddns 192.168.1.1 5533 "$MINIDDNS_SECRET" mycomputer 192.168.1.52
```

## How it works
1. Client makes a request with the hostname it would like to register.
2. Server receives request and updates /etc/hosts with a padded entry.
   1. Search hosts file line by line for the matching IP address.
   2. Replace line with new entry.
   3. If no entry is found, append new entry to host file.

## Message format
See the shell script client for more details.
```
$secret=<user_input> (Eg. bad-random-secret)
$ip=<user_input> (Eg. 192.168.1.1)
$domains=<user_input> (Eg. "mycomputer linuxlaptop")
$message="$ip $domains"
$salt=<random_string>
$hash=sha256($salt$secret$message)

auth-$salt-$hash $message
```


## Roadmap
- [ ] Allow unauthenticated to add hostname for their own IP. (Only useful for machines not traversing NAT)
- [ ] Only allow authenticated requests.
- [ ] Only allow requests for a specific domain.
- [ ] Tests
  - [ ] Open TCP connection but no sent message should timeout on server