# OpenVPN-Review

**DISCLAIMER:** This tool is currently in the beta phase. Unexpected behaviour, bugs or unsupported cipher suites may very likely still exist. Any reported issue is appreciated.

---

[[DE version]](README.de.md)

OpenVPN-Review is a tool, written in `python3`, to evaluate the security of an [OpenVPN Community](https://openvpn.net/index.php/open-source.html) configuration file.
It is mainly intended for server configuration files, but client configuration files may also be evaluated.

**The grade(s) should not be interpreted as an absolute proof for security, more as a guideline for possible improvement.**

Please report any encountered bugs, suggestions or critique by opening an issue on [the GitHub repository](https://github.com/securai/openvpn-review).

If you come across any unimplemented (marked as *unknown* in the script's output) data- and/or control-channel cipher(suites) or hashing functions, file an issue on [the GitHub repository](https://github.com/securai/openvpn-review) for them to be implemented in near future.

Thank you for your participation!


[![Securai](/img/securai.png)](https://securai.de)

[![Contact](/img/mail.png)](https://www.securai.de/en/contact/)


## Installation

GitHub:

 * [![Clone or download](/img/cod.png)](https://github.com/securai/openvpn-review/archive/master.zip)
 * Extract
 * `$ python3 openvpn-review.py`

PyPi:

 * Coming soon.

## Usage

```
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        The OpenVPN configuration file (default /etc/openvpn/server/server.conf)
  -s, --server          Flag to define that the script is running on the OpenVPN server. The default tls-cipher for the server can only be identified on the server itself.
                        If the script is executed on a differnt system and this flag is set, the results may be distorted.
                        If the default tls-cipher is configured and the script is not executed on the server, the results will be incomplete.
  -m, --mbedtls         Flag to define that mbedTLS is used for OpenVPN.
  -v, --verbose         Verbose mode
  -vv, --veryverbose    Very verbose mode
```


## Example

For this example the sample config files from the [official OpenVPN GitHub](https://github.com/OpenVPN/openvpn/tree/master/sample/sample-config-files) (removed comments) are used.

```
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-CBC
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
```


### OpenVPN server configuration review (without -s/--server)

![OpenVPN server configuration review (without -s/--server)](/img/wo.png)

The `tls-cipher` is unknown, as the configuration file does not specify any ciphersuites, thus the default value is configured. This default depends on the deployed SSL library and the script is not executed in the server mode, rendering it unable to identify the ciphersuite(s).

### OpenVPN server configuration review (with -s/--server)

![OpenVPN server configuration review (with -s/--server)](/img/w.png)

With the server mode enabled, the script uses the local SSL library to identify the default value and validates the ciphersuite(s) accordingly.

## To Do

 * Implement a warning if the user's OpenVPN version is greater than the tool's last checked OpenVPN version. This should counter issues between OpenVPN and this tool's updates.
 * Add support for the `--reneg*` options
 * Add support for the `--keysize n` option
 * Revaluate the rating of the `--prng` option
 * :suspect:


## Preview

This script will be supplemented with a second tool, allowing the security assessement from the client perspective without insight on the server configuration (similar to tools like SSLScan).

---
[Mozilla Public License Version 2.0](https://www.mozilla.org/media/MPL/2.0/index.txt)