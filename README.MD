A simple username wordlist generator for kerberute. I made this a while ago for HTB.


```
Usage: ls-ad-users [OPTIONS] --target <TARGET> --domain <DOMAIN> --username <USERNAME> --password <PASSWORD>

Options:
  -t, --target <TARGET>      DC Target (e.g. dc01.domain.local)
  -d, --domain <DOMAIN>      Domain (e.g. domain.local)
  -u, --username <USERNAME>  Username
  -p, --password <PASSWORD>  Password
  -o, --output <OUTPUT>      Output file path [default: users.txt]
  -h, --help                 Print help
  -V, --version              Print version
```


Example usage:

```
proxychains ls-ad-users --target 172.16.7.3 --domain DOMAIN.LOCAL --username T500 --password barrel
...
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.7.3:389  ...  OK
Created user list with 1000 entries.
```


Installing it in userland on kali 

```
sudo cp ls-ad-users /usr/local/bin/
```