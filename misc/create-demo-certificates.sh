#!/bin/sh
# Creates the self-signed certificates of the demo SP and the demo IdP, valid for ten years.
# Run from the repository root with a JDK on the path. The passwords and aliases match the
# configuration in demo/pom.xml and idp/config/application.properties.
set -e

# TLS certificate for localhost, used by the demo SP (Jetty) and the demo IdP (Spring Boot).
# The IdP fetches the SP metadata over TLS and accepts only self-signed certificates.
rm -f misc/ssl-demo.pfx
keytool -genkeypair -alias 1 -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 3650 \
    -dname "CN=localhost, O=OIOSAML demo, C=DK" -ext "SAN=dns:localhost,ip:127.0.0.1" \
    -storetype PKCS12 -keystore misc/ssl-demo.pfx -storepass Test1234 -keypass Test1234
cp misc/ssl-demo.pfx idp/src/main/resources/ssl-demo.pfx
keytool -exportcert -rfc -alias 1 -keystore misc/ssl-demo.pfx -storepass Test1234 -file misc/ssl-demo.cer

# Signing and encryption certificate of the demo IdP. The IdP looks the key up by the alias 1.
idp_password=$(grep '^keystore.password=' idp/config/application.properties | cut -d= -f2-)
rm -f idp/src/main/resources/cert.pfx
keytool -genkeypair -alias 1 -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 3650 \
    -dname "O=Digital Identity, L=Aarhus, ST=Some-State, C=DK" \
    -storetype PKCS12 -keystore idp/src/main/resources/cert.pfx -storepass "$idp_password" -keypass "$idp_password"

echo "Start the demo IdP and save https://localhost:7080/saml/metadata as demo/src/main/resources/test-idp-metadata.xml"
