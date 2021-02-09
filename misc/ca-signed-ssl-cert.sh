#!/usr/bin/bash
set -e

######################
# Become a Certificate Authority
######################

## Root
# Generate private key

# Generate RSASSA-PSS private key for CA
# The key size is 2048; the exponent is 65537
#openssl genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out myCA.key

openssl genrsa -des3 -out myCA.key -passout pass:Test1234 4096
# Generate root certificate
openssl req -x509 -new -nodes -key myCA.key -out myCA.crt -days 3653 \
 -subj "//C=DK\ST=Jylland\L=Viby\O=Nets\OU=sp\CN=myCA" -config cert-config.cfg -extensions root_exts -passin pass:Test1234

# create truststore
openssl pkcs12 -export -in myCA.crt -inkey myCA.key -out truststore.pfx -passin pass:Test1234 -passout pass:Test1234

######################
# Create CA-signed certs
######################


# Generate a private key
openssl genrsa -out sp.key -passout pass:Test1234  2048
# Create a certificate-signing request
openssl req -new -key sp.key -out sp.csr \
  -subj "//C=DK\ST=Jylland\L=Viby\O=sp\OU=sp\CN=sp" -passin pass:Test1234

# Create the signed certificate
openssl x509 -req -in sp.csr -out sp.crt -days 825 -sha256 \
-CA myCA.crt -CAkey myCA.key -CAcreateserial -extfile cert-config.cfg -extensions server_exts -passin pass:Test1234

rm *.csr
openssl pkcs12 -export -in sp.crt -inkey sp.key -out ssl-demo.pfx -certfile myCA.crt -passin pass:Test1234 -passout pass:Test1234


