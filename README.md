#Sanicap

A python based packet capture sanitizer

##Features
* Clean your pcaps for worry-free sharing
* Can randomize/sequentialize:
    * MAC addresses
    * IPv4/IPv6 addresses
* Integrates with scapy, pyshark, cloud-pcap

##Installation
`setup.py` file coming soon. For now, copy to directory of your project.

##Usage

    >>> from sanicap import sanitize
	>>> sanicap.sanitize('/path/to/test.pcap', sequential=True, ipv4_mask=8, ipv6_mask=16)
     This file has 23 IP/IPv6 endpoints and 6 MAC endpoints

##ToDo
* Add pcapng support
* standalone CLI usage
* Anonymize DNS Queries
* Anonymize HTTP host info
* Anonymize HTTP data? (not sure what yet, maybe just POST data)
* python BPF capture filter (apply to pcap files)