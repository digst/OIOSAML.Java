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
 *   Aage Nielsen <ani@openminds.dk>
 *   Carsten Larsen <cas@schultz.dk>
 *   Kasper Vestergaard Møller<kvm@schultz.dk>
 */
package dk.itst.oiosaml.sp.metadata;

import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.helper.DeveloperHelper;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.service.util.Constants;
import org.apache.commons.configuration.Configuration;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.i18n.filter.UntrustedUrlInput;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.fishwife.jrugged.CircuitBreaker;
import org.fishwife.jrugged.CircuitBreakerConfig;
import org.fishwife.jrugged.CircuitBreakerException;
import org.fishwife.jrugged.CircuitBreakerFactory;
import org.fishwife.jrugged.DefaultFailureInterpreter;
import org.opensaml.xml.security.x509.X509Credential;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Callable;

/**
 * Revocation of certificates are done using the follow methods.
 * 
 * OCSP with Distribution Point from configuration. OCSP with Distribution Point from certificates. CRL with Distribution Point from configuration. CRL with Distribution Point from certificates.
 * 
 * Methods are evaluated from top to bottom until a suitable method is found. In case none of the methods are applicable a log entry will be generated specifying the lack of CLR validation.
 * 
 */
public class CRLChecker {
	private static final Logger log = LoggerFactory.getLogger(CRLChecker.class);
	private static final String AUTH_INFO_ACCESS = X509Extension.authorityInfoAccess.getId();
	private static final CircuitBreakerFactory CIRCUIT_BREAKER_FACTORY = new CircuitBreakerFactory();
	private Timer timer;

	public void checkCertificates(IdpMetadata metadata, final Configuration conf) {
		final long resetTime = conf.getLong(Constants.PROP_CIRCUIT_BREAKER_RESET_TIME_IN_SECONDS) * 1000L;
		final int attemptsBeforeOpening = conf.getInt(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_BEFORE_OPENING);
		final long attemptsWithin = conf.getLong(Constants.PROP_CIRCUIT_BREAKER_ATTEMPTS_WITHIN_IN_SECONDS) * 1000L;
		final long delayBetweenAttempts = conf.getLong(Constants.PROP_CIRCUIT_BREAKER_DELAY_BETWEEN_ATTEMPTS_IN_SECONDS) * 1000L;
		final long certificatesRemainValidPeriod = conf.getLong(Constants.PROP_CERTIFICATES_REMAIN_VALID_PERIOD_IN_SECONDS) * 1000L;

		for (final String entityId : metadata.getEntityIDs()) {
			final Metadata md = metadata.getMetadata(entityId);

			for (final X509Certificate certificate : md.getAllCertificates()) {
				// Close circuit after 5 minutes. Open circuit if four or more attempts fails within 1 minute.
				CircuitBreaker circuitBreaker = CIRCUIT_BREAKER_FACTORY.createCircuitBreaker(certificate.getSubjectDN().toString(), new CircuitBreakerConfig(resetTime, new DefaultFailureInterpreter(attemptsBeforeOpening, attemptsWithin)));
				boolean errorState = false;

				// Always check once ... and continue to check if errors occur. Stop checking when circuit is open.
				do {
					try {
						if (circuitBreaker.invoke(new Callable<Boolean>() {
							public Boolean call() {
								return checkCertificate(conf, entityId, md, certificate);
							}
						})) {
							md.setCertificateValid(certificate, true);
							log.debug("Certificate validated successfully: " + certificate.getSubjectDN());
						}
						else {
							md.setCertificateValid(certificate, false);
							log.debug("Certificate did not validate: " + certificate.getSubjectDN());
						}
						errorState = false; // Stop while loop because call was successful. This is necessary if an exception first has been thrown.
					}
					catch (CircuitBreakerException cbe) {
						RevokeCertificateIfRemainValidPeriodIsExpired(md, certificate, cbe, certificatesRemainValidPeriod);
						errorState = false; // Stop while loop because circuit is open.
					}
					catch (Exception e) {
						RevokeCertificateIfRemainValidPeriodIsExpired(md, certificate, e, certificatesRemainValidPeriod);
						errorState = true; // Continue to try checking certificate.
						try {
							Thread.sleep(delayBetweenAttempts); // Wait 5 seconds and try again.
						}
						catch (InterruptedException e1) {
							// Do nothing
						}
					}
				} while (errorState);
			}
		}
	}

	private static void RevokeCertificateIfRemainValidPeriodIsExpired(Metadata md, X509Certificate certificate, Exception e, long certificatesRemainValidPeriod) {
		final Date lastTimeForCertificationValidation = md.getLastTimeForCertificationValidation(certificate);
		// No need to check if certificate should be revoked if it is not in the valid certificates list.
		if (lastTimeForCertificationValidation != null) {
			final Date lastTimeForCertificationValidationPlusConfiguiredRemainValidPeriod = new Date(lastTimeForCertificationValidation.getTime() + certificatesRemainValidPeriod);
			final Date currentTime = new Date();
			if (currentTime.before(lastTimeForCertificationValidationPlusConfiguiredRemainValidPeriod))
				log.warn("Unexpected error while checking revocation of certificate. Certificate " + certificate.getSubjectDN() + " will remain valid until " + lastTimeForCertificationValidationPlusConfiguiredRemainValidPeriod + " if not validated successfully before.", e);
			else {
				log.error("Unexpected error while checking revocation of certificate. Certificate " + certificate.getSubjectDN() + " has been marked as revoked!!", e);
				md.setCertificateValid(certificate, false);
			}
		}
	}

	/**
	 * First attempt is an OCSP check. If this fail the CRL check is used as fail over.
	 * 
	 * @param conf
	 * @param entityId
	 * @param md
	 * @param certificate
	 * @return
	 */
	private static Boolean checkCertificate(Configuration conf, String entityId, Metadata md, X509Certificate certificate) {
		boolean validated = false;
		Exception error = null;

		final boolean support_self_signed_certificates = conf.getBoolean(Constants.SELF_SIGNED_CERT_SUPPORT, false);
		
		// to support a version of OIOSAML with bad spelling, we allow the bad spelling setting to overwrite the
		// correct version, in case it is set.
		boolean disable_check_on_oces_test_certificates = conf.getBoolean(Constants.DISABLE_OCES_TEST_CRL_CHECK, true);
		final boolean disable_check_on_oces_test_certificates_bad_spelling = conf.getBoolean(Constants.DISABLE_OCES_TEST_CRL_CHECK_BAD_SPELLING, true);
		if (!disable_check_on_oces_test_certificates_bad_spelling) {
			disable_check_on_oces_test_certificates = false;
		}
		
		if (support_self_signed_certificates) {
			boolean selfSigned = certificate.getSubjectDN().equals(certificate.getIssuerDN());

			if (selfSigned) {
				log.info("Certificate is self-signed, skip validation");
				return true;
			}
		}

		if (disable_check_on_oces_test_certificates) {
			String issuerName = certificate.getIssuerDN().getName();
			if (issuerName.indexOf("C=DK") >= 0 && issuerName.indexOf("O=TRUST2408") >= 0 && issuerName.indexOf("Systemtest") >= 0) {
				log.info("Certificate is from OCES-test, skip validation");
				return true;
			}
		}

		try {
			log.debug("Checking if certificate with the following subject is revoked using OCSP: " + certificate.getSubjectDN());
			validated = doOCSPCheck(conf, entityId, md, certificate);
			if (validated)
				log.info("Certificate with the following subject IS NOT marked as revoked using OCSP: " + certificate.getSubjectDN());
			else
				log.info("Certificate with the following subject IS revoked using OCSP: " + certificate.getSubjectDN());
		}
		catch (Exception e) {
			// OCSP check failed. Try CRL check.
			log.warn("Unexpected error while validating certificate using OCSP.", e);
			try {
				log.debug("Checking if certificate with the following subject is revoked using CRL: " + certificate.getSubjectDN());
				validated = doCRLCheck(conf, entityId, md, certificate);
				if (validated)
					log.info("Certificate with the following subject IS NOT marked as revoked using CRL: " + certificate.getSubjectDN());
				else
					log.info("Certificate with the following subject IS revoked using CRL: " + certificate.getSubjectDN());
			}
			catch (Exception ex) {
				log.warn("Unexpected error while validating certificate using CRL.", e);
				error = ex;
			}
		}

		if (error != null) {
			throw new WrappedException(Layer.BUSINESS, error);
		}
		

		return validated;
	}

	/**
	 * Check the revocation status of a public key certificate using OCSP.
	 * 
	 * @param conf
	 * @param entityId
	 * @param md
	 * @param certificate
	 * @return true if an OCSP check was completed, otherwise false.
	 * @throws CertificateException
	 */
	private static boolean doOCSPCheck(Configuration conf, String entityId, Metadata md, X509Certificate certificate) throws CertificateException, CertPathValidatorException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		boolean revoked;

		String ocspServer = getOCSPUrl(conf, entityId, certificate);

		if (ocspServer == null) {
			final String message = "No OCSP access location could be found for " + entityId;
			log.debug(message);
			throw new RuntimeException(message);
		}

		log.debug("Starting OCSP validation of certificate " + certificate.getSubjectDN());

		X509Certificate ca = getCertificateCA(conf);
		if (ca == null) {
			throw new RuntimeException("CA Certificate for OCSP check could not be retrieved!");
		}

		// Create certificate chain
		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		certList.add(certificate);
		// certList.add(ca);
		CertPath cp;

		CertificateFactory cf;
		cf = CertificateFactory.getInstance("X.509");
		cp = cf.generateCertPath(certList);

		// Enable OCSP
		Security.setProperty("ocsp.enable", "true");
		Security.setProperty("ocsp.responderURL", ocspServer);

		try {
			TrustAnchor anchor = new TrustAnchor(ca, null);
			PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
			params.setRevocationEnabled(true);

			// Validate and obtain results
			CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
			cpv.validate(cp, params);

			log.debug("Certificate successfully validated during OCSP check.");
			revoked = false;
		}
		catch (CertPathValidatorException cpve) {
			if ("Certificate has been revoked".equals(cpve.getMessage())) {
				revoked = true;
				log.info("Certificate revoked, cert[" + cpve.getIndex() + "] :" + cpve.getMessage());
			}
			else {
				log.error("Validation failure, cert[" + cpve.getIndex() + "] :" + cpve.getMessage());
				throw cpve;
			}
		}

		if (!revoked)
			Audit.log(Operation.OCSPCHECK, false, entityId, "Revoked: NO");
		else
			Audit.log(Operation.OCSPCHECK, false, entityId, "Revoked: YES");

		return !revoked;
	}

	private static X509Certificate getCertificateCA(Configuration conf) throws CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate ca = null;
		InputStream is = null;

		String caPath = conf.getString(Constants.PROP_OCSP_CA);

		try {
			if (caPath == null) {
				log.debug("CA certificate path is not configured");
				return null;
			}

			log.debug("Fetching CA certificate located at: " + caPath);

			URL u = new URL(caPath);
			is = u.openStream();
			ca = (X509Certificate) cf.generateCertificate(is);
			is.close();

		}
		catch (CertificateException e) {
			log.error("Unable to read CA certficate from: " + caPath, e);
			return null;
		}
		catch (Exception e) {
			DeveloperHelper.log("The OIOSAML library default configuration checks for the trusted CA certificate in the /temp/ folder - you can change this configuration with the oiosaml-sp.ocsp.ca property setting");
			
			log.error("Unexpected error while reading CA certficate from: " + caPath, e);
			return null;
		}
		finally {
			if (is != null) {
				try {
					is.close();
				}
				catch (IOException e) {
				}
			}
		}

		return ca;
	}

	/**
	 * Gets an URL to use when performing an OCSP validation of a certificate.
	 * 
	 * @param conf
	 * @param entityId
	 * @param certificate
	 * @return the URL to use.
	 * @see <a href="http://oid-info.com/get/1.3.6.1.5.5.7.48.1">http://oid-info.com/get/1.3.6.1.5.5.7.48.1</a>
	 */
	private static String getOCSPUrl(Configuration conf, String entityId, X509Certificate certificate) {
		String url = conf.getString(Constants.PROP_OCSP_RESPONDER);

		if (url != null) {
			return url;
		}

		log.debug("No OCSP configured for " + entityId + " attempting to extract OCSP location from certificate " + certificate.getSubjectDN());

		AuthorityInformationAccess authInfoAcc = null;
		ASN1InputStream aIn = null;

		try {
			byte[] bytes = certificate.getExtensionValue(AUTH_INFO_ACCESS);
			aIn = new ASN1InputStream(bytes);
			ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
			aIn.close();

			aIn = new ASN1InputStream(octs.getOctets());
			ASN1Primitive auth_info_acc = aIn.readObject();
			aIn.close();

			if (auth_info_acc != null) {
				authInfoAcc = AuthorityInformationAccess.getInstance(auth_info_acc);
			}
		}
		catch (Exception e) {
			log.debug("Cannot extract access location of OCSP responder.", e);
			return null;
		}
		finally {
			if (aIn != null) {
				try {
					aIn.close();
				}
				catch (IOException e) {
				}
			}
		}

		List<String> ocspUrls = getOCSPUrls(authInfoAcc);
		Iterator<String> urlIt = ocspUrls.iterator();

		while (urlIt.hasNext()) {
			// Just return the first URL
			Object ocspUrl = new UntrustedUrlInput(urlIt.next());
			url = ocspUrl.toString();
		}

		return url;
	}

	private static List<String> getOCSPUrls(AuthorityInformationAccess authInfoAccess) {
		List<String> urls = new ArrayList<String>();

		if (authInfoAccess != null) {
			AccessDescription[] ads = authInfoAccess.getAccessDescriptions();
			for (int i = 0; i < ads.length; i++) {
				if (ads[i].getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
					GeneralName name = ads[i].getAccessLocation();
					if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
						String url = ((DERIA5String) name.getName()).getString();
						urls.add(url);
					}
				}
			}
		}

		return urls;
	}

	/**
	 * Perform revocation check using CRL.
	 * 
	 * @param conf
	 * @param entityId
	 * @param md
	 * @param certificate
	 * @return true if CRL check was completed and the certificate is not revoked.
	 */
	private static boolean doCRLCheck(Configuration conf, String entityId, Metadata md, X509Certificate certificate) throws IOException, CertificateException, CRLException, KeyStoreException, NoSuchAlgorithmException {
		boolean revoked = true;

		String url = getCRLUrl(conf, entityId, certificate);

		if (url == null) {
			final String message = "No CRL url could be found for " + entityId;
			log.debug(message);
			throw new RuntimeException(message);
		}

		InputStream is = null;

		try {
			URL u = new URL(url);
			is = u.openStream();

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) cf.generateCRL(is);

			log.debug("CRL for " + url + ": " + crl);

			if (!checkCRLSignature(crl, certificate, conf)) {
				final String message = "CRL Signature could not be validated!!!";
				Audit.log(Operation.CRLCHECK, false, entityId, message);
				throw new RuntimeException(message);
			}

			X509CRLEntry revokedCertificate = crl.getRevokedCertificate(certificate.getSerialNumber());
			if (revokedCertificate != null) {
				log.debug("Certificate found in revocation list " + certificate.getSubjectDN());
				revoked = true;
			}
			else
				revoked = false;

		}
		finally {
			if (is != null) {
				try {
					is.close();
				}
				catch (IOException e) {
				}
			}
		}

		if (!revoked)
			Audit.log(Operation.CRLCHECK, false, entityId, "Revoked: NO");
		else
			Audit.log(Operation.CRLCHECK, false, entityId, "Revoked: YES");

		return !revoked;
	}

	/**
	 * Get an URL to use when downloading CRL
	 * 
	 * @param conf
	 * @param entityId
	 * @param certificate
	 * @return the URL to use
	 */
	private static String getCRLUrl(Configuration conf, String entityId, X509Certificate certificate) {
		String url = conf.getString(Constants.PROP_CRL + entityId);

		if (url != null) {
			return url;
		}

		log.debug("No CRL configured for " + entityId + " attempting to extract distribution point from certificate " + certificate.getSubjectDN());

		byte[] val = certificate.getExtensionValue("2.5.29.31");

		if (val != null) {
			try {
				CRLDistPoint point = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(val));
				for (DistributionPoint dp : point.getDistributionPoints()) {
					if (dp.getDistributionPoint() == null)
						continue;

					if (dp.getDistributionPoint().getName() instanceof GeneralNames) {
						GeneralNames gn = (GeneralNames) dp.getDistributionPoint().getName();
						for (GeneralName g : gn.getNames()) {
							if (g.getName() instanceof DERIA5String) {
								url = ((DERIA5String) g.getName()).getString();
							}
						}
					}
				}
			}
			catch (IOException e) {
				log.debug("Cannot extract distribution point for certificate.", e);
				throw new RuntimeException(e);
			}
		}

		return url;
	}

	/**
	 * Check whether a certificate revocation list (CRL) has a valid signature.
	 * 
	 * @param crl
	 * @param certificate
	 * @param conf
	 * @return true if signature is valid, otherwise false.
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws IllegalStateException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws WrappedException
	 */
	private static boolean checkCRLSignature(X509CRL crl, X509Certificate certificate, Configuration conf) throws WrappedException, NoSuchAlgorithmException, CertificateException, IllegalStateException, KeyStoreException, IOException {
		if (conf.getString(Constants.PROP_CRL_TRUSTSTORE, null) == null)
			return true;

		CredentialRepository cr = new CredentialRepository();
		cr.getCertificate(SAMLConfigurationFactory.getConfiguration().getKeystore(), conf.getString(Constants.PROP_CRL_TRUSTSTORE_PASSWORD), null);

		for (X509Credential cred : cr.getCredentials()) {
			try {
				crl.verify(cred.getPublicKey());
			}
			catch (Exception e) {
				log.debug("CRL not signed by " + cred);
				return false;
			}
		}

		return true;
	}

	public void startChecker(long period, final IdpMetadata metadata, final Configuration conf) {
		if (timer != null)
			return;

		String proxyHost = conf.getString(Constants.PROP_HTTP_PROXY_HOST);
		String proxyPort = conf.getString(Constants.PROP_HTTP_PROXY_PORT);

		if (proxyHost != null && proxyPort != null) {
			log.debug("Enabling use of proxy " + proxyHost + " port " + proxyPort + " when checking revocation of certificates.");

			System.setProperty("http.proxyHost", proxyHost);
			System.setProperty("http.proxyPort", proxyPort);
		}

		log.info("Starting CRL checker, running with " + period + " seconds interval. Checking " + metadata.getEntityIDs().size() + " certificates");
		timer = new Timer("CRLChecker");
		timer.schedule(new TimerTask() {
			@Override
			public void run() {
				log.debug("Running CRL checker task");

				try {
					checkCertificates(metadata, conf);
				}
				catch (Exception e) {
					log.error("Unable to run CRL checker", e);
				}
			}
		}, 1000L, 1000L * period);
	}

	public void stopChecker() {
		if (timer != null) {
			log.info("Stopping CRL checker");
			timer.cancel();
			timer = null;
		}
	}

	/**
	 * Marks all certificates as valid without making any certificate check.
	 * 
	 * @param metadata
	 *            contains the list of IdP certificates.
	 */
	public void setAllCertificatesValid(IdpMetadata metadata) {
		for (final String entityId : metadata.getEntityIDs()) {
			final Metadata md = metadata.getMetadata(entityId);
			for (final X509Certificate certificate : md.getAllCertificates()) {
				md.setCertificateValid(certificate, true);
			}
		}
	}
}
