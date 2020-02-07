/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.security;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Date;

import org.apache.xml.security.algorithms.JCEMapper;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.Base64;

/**
 * Some utility methods for doing security, credential, key and JCE related tests.
 */
public class SecurityHelper {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
    
	public static final String VERSION = "$Id: SecurityHelper.java 2836 2008-05-14 06:22:24Z jre $";

	private SecurityHelper() { }
    
    /**
     * Build Java certificate from base64 encoding.
     * 
     * @param base64Cert base64-encoded certificate
     * @return a native Java X509 certificate
     * @throws CertificateException thrown if there is an error constructing certificate
     */
    public static java.security.cert.X509Certificate buildJavaX509Cert(String base64Cert) throws CertificateException {
        CertificateFactory  cf = null;
        cf = CertificateFactory.getInstance("X.509");
        
        ByteArrayInputStream input = new ByteArrayInputStream(Base64.decode(base64Cert));
        java.security.cert.X509Certificate newCert = null;
        newCert = (java.security.cert.X509Certificate) cf.generateCertificate(input);
        return newCert;
    }
    
    /**
     * Build Java CRL from base64 encoding.
     * 
     * @param base64CRL base64-encoded CRL
     * @return a native Java X509 CRL
     * @throws CertificateException thrown if there is an error constructing certificate
     * @throws CRLException  thrown if there is an error constructing CRL
     */
    public static java.security.cert.X509CRL buildJavaX509CRL(String base64CRL) 
        throws CertificateException, CRLException {
        CertificateFactory  cf = null;
        cf = CertificateFactory.getInstance("X.509");
        
        ByteArrayInputStream input = new ByteArrayInputStream(Base64.decode(base64CRL));
        java.security.cert.X509CRL newCRL = null;
        newCRL = (java.security.cert.X509CRL) cf.generateCRL(input);
        
        return newCRL;
    }
    
    /**
     * Generates a public key from the given key spec.
     * 
     * @param keySpec {@link KeySpec} specification for the key
     * @param keyAlgorithm key generation algorithm, only DSA and RSA supported
     * 
     * @return the generated {@link PublicKey}
     * 
     * @throws KeyException thrown if the key algorithm is not supported by the JCE or the key spec does not
     *             contain valid information
     */
    public static PublicKey buildKey(KeySpec keySpec, String keyAlgorithm) throws KeyException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyException(keyAlgorithm + "algorithm is not supported by the JCE:" + e.getMessage());
        } catch (InvalidKeySpecException e) {
            throw new KeyException("Invalid key information:" + e.getMessage());
        }
    }
    
    /**
     * Randomly generates a Java JCE KeyPair object from the specified XML Encryption algorithm URI.
     * 
     * @param algoURI  The XML Encryption algorithm URI
     * @param keyLength  the length of key to generate
     * @return a randomly-generated KeyPair
     * @throws NoSuchProviderException  provider not found
     * @throws NoSuchAlgorithmException  algorithm not found
     */
    public static KeyPair generateKeyPairFromURI(String algoURI, int keyLength) 
        throws NoSuchAlgorithmException, NoSuchProviderException {
        String jceAlgorithmName = JCEMapper.getJCEKeyAlgorithmFromURI(algoURI);
        return generateKeyPair(jceAlgorithmName, keyLength, null);
    }
    
    /**
     * Generate a random asymmetric key pair.
     * 
     * @param algo key algorithm
     * @param keyLength key length
     * @param provider JCA provider
     * @return randomly generated key
     * @throws NoSuchAlgorithmException algorithm not found
     * @throws NoSuchProviderException provider not found
     */
    public static KeyPair generateKeyPair(String algo, int keyLength, String provider) 
        throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair keyPair = null;
        KeyPairGenerator keyGenerator = null;
        if (provider != null) {
            keyGenerator = KeyPairGenerator.getInstance(algo, provider);
        } else {
            keyGenerator = KeyPairGenerator.getInstance(algo);
        }
        keyGenerator.initialize(keyLength);
        keyPair = keyGenerator.generateKeyPair();
        return keyPair;
    }
    
    public static X509Certificate generateCertificate(Credential credential, String entityId) throws Exception {
        X500Name issuer = new X500Name("o=keymanager, ou=oiosaml-sp");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60L * 60L * 24L * 365L * 10L);
        X500Name subject = new X500Name("cn=" + entityId + ", ou=oiosaml-sp");

        ByteArrayInputStream bIn = new ByteArrayInputStream(credential.getPublicKey().getEncoded());
        ASN1InputStream asn1in = new ASN1InputStream(bIn);
        SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo((ASN1Sequence) asn1in.readObject());
        asn1in.close();

        X509v3CertificateBuilder gen = new X509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter, subject, publicKeyInfo);

    	gen.addExtension(X509Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(credential.getPublicKey()));
    	gen.addExtension(X509Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(credential.getPublicKey()));

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(credential.getPrivateKey());
        X509CertificateHolder certificateHolder = gen.build(sigGen);

        X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
    	return x509Certificate;
    }
    
}
