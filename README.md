# Usage

ipsetblock allows easy creation of ipsets from block list such as [spamhaus](https://www.spamhaus.org), and [stopforumspam](https://www.stopforumspam.com). 

The IP addresses from the blocklists should be in the ipset form `hash:net`. This can be changed with the method and datatype flags.

Blacklist urls should be placed in the `blacklist_urls` file. 

To add extra IP addresses that don't come from block lists, place them in `blacklist_ips`. IP addresses can also be whitelisted by placing them in the `whitelist_ips` file. These are the default file locations but they can be changed at runtime.

```
$ ipsetblock.py -h
usage: ipsetblock.py [-h] [-v] [-b BLACKLISTED_IPS] [-w WHITELISTED_IPS]
                     [-u BLACKLIST_URLS] [-l LOGFILE] [-m METHOD]
                     [-d DATATYPE]
                     [ipset]

positional arguments:
  ipset

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose
  -b BLACKLISTED_IPS, --blacklisted_ips BLACKLISTED_IPS
  -w WHITELISTED_IPS, --whitelisted_ips WHITELISTED_IPS
  -u BLACKLIST_URLS, --blacklist_urls BLACKLIST_URLS
  -l LOGFILE, --logfile LOGFILE
  -m METHOD, --method METHOD
                        ipset method
  -d DATATYPE, --datatype DATATYPE
                        ipset datatype
```
