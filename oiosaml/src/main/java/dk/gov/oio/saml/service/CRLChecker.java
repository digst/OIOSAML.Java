package dk.gov.oio.saml.service;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.i18n.filter.UntrustedUrlInput;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;

import dk.gov.oio.saml.config.Configuration;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.InternalException;

public class CRLChecker {
	private static final Logger log = LoggerFactory.getLogger(CRLChecker.class);
	private static final String AUTH_INFO_ACCESS = Extension.authorityInfoAccess.getId();
	private static Map<String, X509Certificate> certificateMap = new HashMap<String, X509Certificate>();
	
	public static Set<X509Certificate> checkCertificates(List<X509Certificate> x509Certificates, DateTime lastCRLCheck) throws ExternalException, InternalException, InitializationException {
		Set<X509Certificate> result = new HashSet<>();
		if (x509Certificates == null || x509Certificates.size() == 0) {
			return result;
		}

		// Check all certificates, and return those that are valid
		for (final X509Certificate certificate : x509Certificates) {
			if (checkCertificate(certificate)) {
				result.add(certificate);
				log.debug("Certificate validated successfully: %s", certificate.getSubjectDN());
			}
			else {
				log.error("Certificate did not validate: %s", certificate.getSubjectDN());
			}
		}

		return result;
	}

	// OCSP first if configured, with fallback to CRL if configured
	private static boolean checkCertificate(X509Certificate certificate) {
		boolean validated = false;

		Configuration config = OIOSAML3Service.getConfig();
		if (config.isOcspCheckEnabled()) {
			try {
				validated = doOCSPCheck(certificate);
			}
			catch (Exception e) {
				log.warn("Unexpected error while validating certificate using OCSP.", e);

				if (config.isCRLCheckEnabled()) {
					try {
						validated = doCRLCheck(certificate);
					}
					catch (Exception ex) {
						log.warn("Unexpected error while validating certificate using CRL.", ex);
					}				
				}
			}
		}
		else if (config.isCRLCheckEnabled()) {
			try {
				validated = doCRLCheck(certificate);
			}
			catch (Exception ex) {
				log.warn("Unexpected error while validating certificate using CRL.", ex);
			}				
		}
		else {
			log.warn("checkCertificate called, but both OCSP and CRL checking is disabled");
			validated = true;
		}

		return validated;
	}

	private static boolean doOCSPCheck(X509Certificate certificate) throws CertificateException, CertPathValidatorException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		log.debug("Starting OCSP validation of certificate %s", certificate.getSubjectDN());

		String ocspServer = getOCSPUrl(certificate);
		if (ocspServer == null) {
			throw new RuntimeException("No OCSP access location could be found");
		}

		// try to retrieve issuing OCES CA certificate
		X509Certificate issuer = getIssuingCertificate(certificate);
		if (issuer == null) {
			throw new RuntimeException("CA Certificate for OCSP check could not be retrieved!");
		}

		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		certList.add(certificate);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		CertPath cp = cf.generateCertPath(certList);

		Security.setProperty("ocsp.enable", "true");
		Security.setProperty("ocsp.responderURL", ocspServer);

		boolean revoked;
		try {
			TrustAnchor anchor = new TrustAnchor(issuer, null);
			PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
			params.setRevocationEnabled(true);

			// Validate and obtain results
			CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
			cpv.validate(cp, params);

			log.debug("Certificate successfully validated during OCSP check.");
			revoked = false;
		}
		catch (CertPathValidatorException cpve) {
			if (cpve.getMessage() != null && cpve.getMessage().contains("Certificate has been revoked")) {
				revoked = true;
				log.info("Certificate revoked, cert[%s] : %s", cpve.getIndex(), cpve.getMessage());
			}
			else {
				log.error("Validation failure, cert[%s] : %s", cpve.getIndex(), cpve.getMessage());
				throw cpve;
			}
		}

		return (!revoked);
	}

	private static X509Certificate getIssuingCertificate(X509Certificate certificate) {
		log.debug("Attempting to extract issuing ca certifcate from certificate %s", certificate.getSubjectDN());

		AuthorityInformationAccess authInfoAcc = null;

		try {
			byte[] bytes = certificate.getExtensionValue(AUTH_INFO_ACCESS);

			try (ASN1InputStream aIn = new ASN1InputStream(bytes)) {
				ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
	
				try (ASN1InputStream aIn2 = new ASN1InputStream(octs.getOctets())) {
					ASN1Primitive auth_info_acc = aIn2.readObject();
		
					if (auth_info_acc != null) {
						authInfoAcc = AuthorityInformationAccess.getInstance(auth_info_acc);
					}
				}
			}
		}
		catch (Exception e) {
			log.debug("Cannot extract access location of issuing ca.", e);
			return null;
		}

		List<String> issuingCaUrls = getIssuingCAUrls(authInfoAcc);
		Iterator<String> urlIt = issuingCaUrls.iterator();
		while (urlIt.hasNext()) {
			Object caUrl = new UntrustedUrlInput(urlIt.next());

			return downloadCertificate(caUrl.toString());			
		}

		return null;
	}
	
	private static X509Certificate downloadCertificate(String url) {
		if (certificateMap.containsKey(url)) {
			return certificateMap.get(url);
		}
		
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			try (InputStream is = new URL(url).openStream()) {
				X509Certificate certificate = (X509Certificate) factory.generateCertificate(is);
				if (certificate != null) {
					certificateMap.put(url, certificate);
					
					return certificate;
				}
				
				log.warn("Failed to parse certificate from %s", url);
			}
			catch (IOException ex) {
				log.warn("Failed to download intermediate CA certificate from %s", url);
			}
		}
		catch (CertificateException ex) {
			log.warn("Failed to generate certificate factory", ex);
		}

		return null;
	}

	private static String getOCSPUrl(X509Certificate certificate) {
		log.debug("Attempting to extract OCSP location from certificate %s", certificate.getSubjectDN());

		AuthorityInformationAccess authInfoAcc = null;

		try {
			byte[] bytes = certificate.getExtensionValue(AUTH_INFO_ACCESS);
			try (ASN1InputStream aIn = new ASN1InputStream(bytes)) {
				ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
	
				try (ASN1InputStream aIn2 = new ASN1InputStream(octs.getOctets())) {
					ASN1Primitive auth_info_acc = aIn2.readObject();
		
					if (auth_info_acc != null) {
						authInfoAcc = AuthorityInformationAccess.getInstance(auth_info_acc);
					}
				}
			}
		}
		catch (Exception e) {
			log.debug("Cannot extract access location of OCSP responder.", e);
			return null;
		}

		List<String> ocspUrls = getOCSPUrls(authInfoAcc);
		Iterator<String> urlIt = ocspUrls.iterator();

		while (urlIt.hasNext()) {
			Object ocspUrl = new UntrustedUrlInput(urlIt.next());

			return ocspUrl.toString();
		}

		return null;
	}

	private static List<String> getIssuingCAUrls(AuthorityInformationAccess authInfoAccess) {
		List<String> urls = new ArrayList<String>();

		if (authInfoAccess != null) {
			AccessDescription[] ads = authInfoAccess.getAccessDescriptions();
			for (int i = 0; i < ads.length; i++) {
				if (ads[i].getAccessMethod().equals(AccessDescription.id_ad_caIssuers)) {
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

	private static boolean doCRLCheck(X509Certificate certificate) throws IOException, CertificateException, CRLException, InitializationException {
		boolean revoked = true;

		String url = getCRLUrl(certificate);
		if (url == null) {
			throw new RuntimeException("No CRL url could be found");
		}

		URL u = new URL(url);
		try (InputStream is = u.openStream()) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) cf.generateCRL(is);

			log.debug("CRL for %s: %s", url, crl);

			X509CRLEntry revokedCertificate = crl.getRevokedCertificate(certificate.getSerialNumber());
			if (revokedCertificate != null) {
				log.warn("Certificate found in revocation list " + certificate.getSubjectDN());
				revoked = true;
			}
			else {
				revoked = false;
			}
		}

		return !revoked;
	}

	private static String getCRLUrl(X509Certificate certificate) throws IOException {
		log.debug("Attempting to extract distribution point from certificate %s", certificate.getSubjectDN());

		byte[] val = certificate.getExtensionValue("2.5.29.31");
		if (val != null) {
			CRLDistPoint point = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(val));
			for (DistributionPoint dp : point.getDistributionPoints()) {
				if (dp.getDistributionPoint() == null) {
					continue;
				}

				if (dp.getDistributionPoint().getName() instanceof GeneralNames) {
					GeneralNames gn = (GeneralNames) dp.getDistributionPoint().getName();
					for (GeneralName g : gn.getNames()) {
						if (g.getName() instanceof DERIA5String) {
							return ((DERIA5String) g.getName()).getString();
						}
					}
				}
			}
		}

		return null;
	}
}
