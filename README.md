# Sanicap

A python based packet capture sanitizer

## Features
* Clean your pcaps for worry-free sharing
* Can randomize/sequentialize:
    * MAC addresses
    * IPv4/IPv6 addresses
* Override VLAN number
* Integrates with scapy, pyshark, cloud-pcap

## Installation
- A `setup.py` file is coming soon. For now, copy to directory of your project.
- to build a docker container, check out this repository and then run `docker build -t sanicap` in the
top level directory.

## Usage
### In another python script
```python
>>> from sanicap import sanitize
>>> sanicap.sanitize('/path/to/test.pcap', sequential=True, ipv4_mask=8, ipv6_mask=16)
This file has 23 IPv4/IPv6 endpoints and 6 MAC endpoints
File created: /path/to/test_sanitized_141205-124237.pcap
```

### As a CLI utility
The examples below use the docker container, but this would also work if the dependencies in `requirements.txt` are 
installed directly on your system.
#### Help:
```console
$ docker run -ti sanicap -h
usage: sanicap.py [-h] [-o FILEPATH_OUT] [-s SEQUENTIAL] [-a APPEND] [--ipv4mask IPV4MASK] [--ipv6mask IPV6MASK]
                  [--macmask MACMASK] [--startipv4 STARTIPV4] [--startipv6 STARTIPV6] [--startmac STARTMAC]
                  [--fixedvlan FIXEDVLAN]
                  filepath_in

positional arguments:
  filepath_in           The pcap file to sanitize.

optional arguments:
  -h, --help            show this help message and exit
  -o FILEPATH_OUT, --filepath_out FILEPATH_OUT
                        File path to store the sanitized pcap.
  -s SEQUENTIAL, --sequential SEQUENTIAL
                        Use sequential IPs/MACs in sanitization.
  -a APPEND, --append APPEND
                        Append to, instead of overwriting output file..
  --ipv4mask IPV4MASK   Apply a mask to sanitized IPv4 addresses (Eg. mask of 8 preserves first octet).
  --ipv6mask IPV6MASK   Apply a mask to sanitized IPv6 addresses (Eg. mask of 16 preserves first chazwazza).
  --macmask MACMASK     Apply a mask to sanitized IPv6 addresses (Eg. mask of 24 preserves manufacturer).
  --startipv4 STARTIPV4
                        Start sequential IPv4 sanitization with this IPv4 addresses.
  --startipv6 STARTIPV6
                        Start sequential IPv6 sanitization with this IPv6 addresses.
  --startmac STARTMAC   Start sequential MAC sanitization with this MAC addresses.
  --fixedvlan FIXEDVLAN
                        Overwrite VLANID (fixed)

    usage: sanicap.py [-h] [-o FILEPATH_OUT] [-s SEQUENTIAL] [--ipv4mask IPV4MASK]
                      [--ipv6mask IPV6MASK] [--macmask MACMASK]
                      [--startipv4 STARTIPV4] [--startipv6 STARTIPV6]
                      [--startmac STARTMAC]
                      filepath_in
```
#### Example:
```console
$ docker run -ti -v $(pwd):/data sanicap /data/test.pcap -o /data/out.pcap -s True --ipv4mask=8
This file has 85 IPv4/IPv6 endpoints and 38 MAC endpoints
File created: /data/out.pcap
```

## ToDo
* Add pcapng support
* standalone CLI usage
* Anonymize DNS Queries
* Anonymize HTTP host info
* Anonymize HTTP data? (not sure what yet, maybe just POST data)
* python BPF capture filter (apply to pcap files)
