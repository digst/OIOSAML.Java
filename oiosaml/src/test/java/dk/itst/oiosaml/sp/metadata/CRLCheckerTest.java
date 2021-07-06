package dk.itst.oiosaml.sp.metadata;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.security.x509.X509Credential;

import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.Constants;


public class CRLCheckerTest extends AbstractTests {
	
	private IdpMetadata idp;
	private CRLChecker checker;
	private X509Credential cred;


	@Before
	public void setUp() throws Exception {
		cred = TestHelper.getCredential();
		EntityDescriptor buildIdPMetadata = TestHelper.buildEntityDescriptor(cred);
		
		idp = new IdpMetadata(SAMLConstants.SAML20P_NS, buildIdPMetadata);
		checker = new CRLChecker();
	}
	
	@After
	public void stopTimer() {
		checker.stopChecker();
	}
	

	@Test
	public void testCheckCertificatesWithNoRevoked() throws Exception {
		checker.checkCertificates(idp, TestHelper.buildConfiguration(new HashMap<String, String>() {{
            put(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_BEFORE_OPENING, "3");
            put(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_WITHIN_IN_SECONDS, "60");
            put(Constants.PROP_CIRCUIT_BREAKER_DELAY_BETWEEN_ATTEMPTS_IN_SECONDS, "5");
            put(Constants.PROP_CIRCUIT_BREAKER_RESET_TIME_IN_SECONDS, "300");
            put(Constants.PROP_CERTIFICATES_REMAIN_VALID_PERIOD_IN_SECONDS, "3600");
        }}));

		assertNotNull(idp.getFirstMetadata().getValidCertificates());
	}
	
	
	@Test
	public void testRevoked() throws Exception {
		X509Certificate cert = (X509Certificate) idp.getFirstMetadata().getCertificates().iterator().next();
		
		final File crlFile = generateCRL(cert);

		Configuration conf = TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_CRL + idp.getFirstMetadata().getEntityID(), crlFile.toURI().toString());
            put(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_BEFORE_OPENING, "3");
            put(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_WITHIN_IN_SECONDS, "60");
            put(Constants.PROP_CIRCUIT_BREAKER_DELAY_BETWEEN_ATTEMPTS_IN_SECONDS, "5");
            put(Constants.PROP_CIRCUIT_BREAKER_RESET_TIME_IN_SECONDS, "300");
            put(Constants.PROP_CERTIFICATES_REMAIN_VALID_PERIOD_IN_SECONDS, "3600");
		}});
		
		checker.checkCertificates(idp, conf);

		assertEquals(0, idp.getFirstMetadata().getValidCertificates().size());
	}


//	@Test(expected=InvalidCertificateException.class)
	@Test
	public void testTimer() throws Exception {
		X509Certificate cert = (X509Certificate) idp.getFirstMetadata().getCertificates().iterator().next();

		final File crlFile = generateCRL(null);

		Configuration conf = TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_CRL + idp.getFirstMetadata().getEntityID(), crlFile.toURI().toString());
			put(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_BEFORE_OPENING, "3");
			put(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_WITHIN_IN_SECONDS, "60");
			put(Constants.PROP_CIRCUIT_BREAKER_DELAY_BETWEEN_ATTEMPTS_IN_SECONDS, "5");
			put(Constants.PROP_CIRCUIT_BREAKER_RESET_TIME_IN_SECONDS, "300");
			put(Constants.PROP_CERTIFICATES_REMAIN_VALID_PERIOD_IN_SECONDS, "3600");
		}});
		
		assertNotNull(idp.getFirstMetadata().getValidCertificates());
		
		checker.startChecker(1, idp, conf);
		Thread.sleep(1500);
		assertNotNull(idp.getFirstMetadata().getValidCertificates());

		crlFile.delete();
		generateCRL(cert).renameTo(crlFile);
		
		Thread.sleep(1500);
		
		assertEquals(0, idp.getFirstMetadata().getValidCertificates().size());
	}
	
	@Test
	public void invalid_signature_on_crl_should_fail() throws Exception {
		final File crlFile = generateCRL(null);

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null, "password".toCharArray());
		ks.setCertificateEntry("trust", TestHelper.getCredential().getEntityCertificate());
		
		final File keystore = File.createTempFile("test", "test");
		ks.store(new FileOutputStream(keystore), "password".toCharArray());
		
		Configuration conf = TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_CRL + idp.getFirstMetadata().getEntityID(), crlFile.toURI().toString());
			put(Constants.PROP_CRL_TRUSTSTORE, keystore.getAbsolutePath());
			put(Constants.PROP_CRL_TRUSTSTORE_PASSWORD, "password");
			put(Constants.PROP_CERTIFICATE_PASSWORD, "password");
			put(Constants.PROP_CERTIFICATE_LOCATION,keystore.getAbsolutePath());
            put(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_BEFORE_OPENING, "3");
            put(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_WITHIN_IN_SECONDS, "60");
            put(Constants.PROP_CIRCUIT_BREAKER_DELAY_BETWEEN_ATTEMPTS_IN_SECONDS, "5");
            put(Constants.PROP_CIRCUIT_BREAKER_RESET_TIME_IN_SECONDS, "300");
            put(Constants.PROP_CERTIFICATES_REMAIN_VALID_PERIOD_IN_SECONDS, "3600");
		}});

		SAMLConfiguration sc = SAMLConfigurationFactory.getConfiguration();
		Map<String,String> params=new HashMap<String, String>();
		//params.put(Constants.INIT_OIOSAML_HOME, null);
		sc.setInitConfiguration(params);
		sc.setConfiguration(conf);

		checker.checkCertificates(idp, conf);
		
		assertEquals(0, idp.getFirstMetadata().getValidCertificates().size());
	}
	
	@Test
	public void crl_should_be_signed_if_truststore_specified() throws Exception {
		final File crlFile = generateCRL(null);

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null, "password".toCharArray());
		ks.setCertificateEntry("trust", cred.getEntityCertificate());
		
		final File keystore = File.createTempFile("test", "test");
		ks.store(new FileOutputStream(keystore), "password".toCharArray());
		
		Configuration conf = TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_CRL + idp.getFirstMetadata().getEntityID(), crlFile.toURI().toString());
			put(Constants.PROP_CRL_TRUSTSTORE, keystore.getAbsolutePath());
			put(Constants.PROP_CRL_TRUSTSTORE_PASSWORD, "password");
			put(Constants.PROP_CERTIFICATE_PASSWORD, "password");
			put(Constants.PROP_CERTIFICATE_LOCATION,keystore.getAbsolutePath());
            put(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_BEFORE_OPENING, "3");
            put(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_WITHIN_IN_SECONDS, "60");
            put(Constants.PROP_CIRCUIT_BREAKER_DELAY_BETWEEN_ATTEMPTS_IN_SECONDS, "5");
            put(Constants.PROP_CIRCUIT_BREAKER_RESET_TIME_IN_SECONDS, "300");
            put(Constants.PROP_CERTIFICATES_REMAIN_VALID_PERIOD_IN_SECONDS, "3600");
		}});

		SAMLConfiguration sc = SAMLConfigurationFactory.getConfiguration();
		Map<String,String> params=new HashMap<String, String>();
		//params.put(Constants.INIT_OIOSAML_HOME, null);
		sc.setInitConfiguration(params);
		sc.setConfiguration(conf);
		
		checker.checkCertificates(idp, conf);
		
		assertEquals(1, idp.getFirstMetadata().getCertificates().size());
	}
	
	private File generateCRL(X509Certificate cert) throws CRLException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, OperatorCreationException {
        X500Name issuer = new X500Name("CN=ca");
        Date thisUpdate = new Date();
        X509v2CRLBuilder gen = new X509v2CRLBuilder(issuer, thisUpdate);
		gen.setNextUpdate(new Date(System.currentTimeMillis() + 60000));

        if (cert != null) {
			gen.addCRLEntry(cert.getSerialNumber(), new Date(System.currentTimeMillis() - 1000), CRLReason.keyCompromise);
		}

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(cred.getPrivateKey());
		X509CRLHolder crl = gen.build(sigGen);

		final File crlFile = File.createTempFile("test", "test");
		crlFile.deleteOnExit();
		FileOutputStream fos = new FileOutputStream(crlFile);
		IOUtils.write(crl.getEncoded(), fos);
		fos.close();
		return crlFile;
	}


}
