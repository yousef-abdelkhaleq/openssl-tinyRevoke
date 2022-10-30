# Openssl-tinyOCSP

Openssl-tinyOCSP adds the functionality to request a C509 profiled CBOR encoded OCSP response (TinyOCSP response). The implementation aims to support acquiring and processing Certificate Revocation information in Resource Constrained Environments.

## Installation
The steps below show how to install the repo's version of openssl without it affecting a system installation of openssl.

	- cd into the openssl folder
		-> cd openssl-3.0.5
	- Configure and compile OpenSSL with commands below.
		-> ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
		-> sudo make install
	- Note: --prefix and --openssldir = Set the output path of the OpenSSL.
			shared = force to create a shared library.
			zlib = enable the compression using zlib library.



