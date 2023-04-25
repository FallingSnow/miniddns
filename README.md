# MINIDDNSD
miniddnsd adds host entries to your hosts file.

## Compile
Make sure you have rust and cargo installed.
```
$ cargo run build --release
$ ls target/release/miniddnsd
```

## Usage
### Server
```sh
$ export MINIDDNS_SECRET=`tr -dc 'A-Za-z0-9' </dev/urandom | head -c 128`
$ miniddnsd
```

To run the server in a production manner, save the secret to a file so it can be loaded again at reboot. Then cat the file into the `MINIDDNS_SECRET` environmental variable.
```sh
$ tr -dc 'A-Za-z0-9' </dev/urandom | head -c 128 > .miniddns_secret
chmod 400 .miniddns_secret
$ 
$ MINIDDNS_SECRET=`cat .miniddns_secret` miniddnsd
```

#### Server Environmental Variables
* `MINIDDNS_SECRET` - Define the secret used to authenticate tcp packets. This should be stored on the server and clients. This has no default and must be defined.
* `MINIDDNS_ADDRESS` - Define the ip address you would like to bind to. Defaults to `0.0.0.0` (all interfaces).
* `MINIDDNS_PORT` - Define the port to listen on. Defaults to `5533`.
* `MINIDDNS_HOSTS_PATH` - Define the file you wish to update with ddns records. Defaults to `/etc/hosts`.
* `MINIDDNS_FORCE_AUTO` - If set (even to false) clients are required to have `target_ip` set to `auto`. The server then use's the incomming packet's ip header as the target_ip. `auto` doesn't work with packets traversing NAT.

### Client
miniddns is just a shell script located at the root level of this repository that sends a tcp message. The `MINIDDNS_SECRET` must be the same as used on the server above. See `miniddns --help` for more info.
```sh
$ wget https://raw.githubusercontent.com/FallingSnow/miniddns/master/miniddns
$ chmod +x miniddns
$ ./miniddns --help
$ ./miniddns 192.168.1.1 5533 $MINIDDNS_SECRET mycomputer 192.168.1.52
```

You can also allow the server to use the IP of the packet you send by setting `target_ip` to `auto`. Do not use this over NAT.
```sh
$ ./miniddns 192.168.1.1 5533 $MINIDDNS_SECRET mycomputer auto
```

Here is an example where you read your secret from a file and use the hostname of your system.
```sh
$ echo $MINIDDNS_SECRET > .miniddns_secret
$ chmod 400 .miniddns_secret
$ ./miniddns 192.168.1.1 5533 `cat .miniddns_secret` `hostname` auto
```

## How it works
1. Client makes a request with the hostname it would like to register.
2. Server receives request and updates /etc/hosts with a padded entry.
   1. Search hosts file line by line for the matching IP address.
   2. Replace line with new entry.
   3. If no entry is found, append new entry to host file.

## Message format
See the `miniddns` client script for more details.
```sh
$secret=<user_input> (Eg. bad-random-secret)
$ip=<user_input> (Eg. 192.168.1.1)
$domains=<user_input> (Eg. "mycomputer linuxlaptop")
$message="$ip $domains"
$salt=<random_string>
$hash=sha256($salt$secret$message)
```
```
auth-$salt-$hash $message
```


## Roadmap
- [ ] Allow unauthenticated to add hostname for their own IP. (Only useful for machines not traversing NAT)
- [ ] Only allow authenticated requests.
- [ ] Only allow requests for a specific domain.
- [ ] Tests
  - [ ] Open TCP connection but no sent message should timeout on server
  - [ ] Auth messages
  - [ ] Non auth messages