# bro TLS handshake detector script

Intercept TLS handshakes and log the certificate's hash, domain name, and the base64 encoded certificate into kafka. 

## Installation

Installing bro and bro-kafka plugin:
 - [build bro from source](https://github.com/bro/bro/blob/master/doc/install/install.rst)
 - [build kafka plugin](https://github.com/bro/bro-plugins/tree/master/kafka)
 - [Running/testing kafka (on MacOs X)](https://dtflaneur.wordpress.com/2015/10/05/installing-kafka-on-mac-osx/)
