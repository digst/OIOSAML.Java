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
 *
 */
package dk.itst.oiosaml.sp.configuration;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.FileConfiguration;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.service.RequestContext;
import dk.itst.oiosaml.sp.service.SAMLHandler;
import dk.itst.oiosaml.sp.service.util.Constants;

/**
 * Configuration hander for initial OIOSAML-J configuration.
 * 
 * <p>
 * This servlet is used when the system has not yet been configured correctly. It checks if oiosaml-j.home points to an existing dir. If the dir is empty, configuration can proceed. As a security precaution, configuration can never proceed if the configuration dir is not empty.
 * </p>
 * 
 * <p>
 * On a normal GET, a page with a form is displayed. SAML EntityID and endpoint URLs are autodetected based on the requested url.
 * </p>
 * 
 * <p>
 * The user can upload IdP metadata, SP certificate, and fill out some additional required info. When the completed form is POSTed, a new SP metadata file is generated together with the necessary property files. All of this is written to a ZIP-file, which can be downloaded. If the home dir is
 * writable, the generated files will also be placed there automatically.
 * </p>
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Aage Nielsen <ani@openminds.dk>
 *
 */
public class ConfigurationHandler implements SAMLHandler {
	public static final String SESSION_CONFIGURATION = "CONFIGURATION";
	private static final Logger log = LoggerFactory.getLogger(ConfigurationHandler.class);
	protected final VelocityEngine engine;

	public ConfigurationHandler() {
		engine = new VelocityEngine();
		engine.setProperty(VelocityEngine.RESOURCE_LOADER, "classpath");
		engine.setProperty("classpath.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		try {
			engine.init();
		}
		catch (Exception e) {
			log.error("Unable to initialize Velocity", e);
			throw new WrappedException(Layer.BUSINESS, e);
		}
	}

	public void handleGet(RequestContext context) throws ServletException, IOException {
		HttpServletRequest request = context.getRequest();
		HttpServletResponse response = context.getResponse();

		if (request.getParameter("download") != null) {
			byte[] conf = (byte[]) request.getSession().getAttribute(SESSION_CONFIGURATION);
			if (conf == null) {
				response.sendError(HttpServletResponse.SC_NOT_FOUND, "No configuration available for download");
				return;
			}
			
			response.setContentType("application/octet-stream");
			response.setContentLength(conf.length);
			response.addHeader("Content-disposition", "attachment; filename=oiosaml.java-config.zip");
			response.getOutputStream().write(conf);
			return;
		}
		
		if (!checkConfiguration(response)) {
			return;
		}

		Map<String, Object> params = getStandardParameters(request);

		String res = renderTemplate("configure.vm", params, true);
		sendResponse(response, res);
	}

	public void handlePost(RequestContext context) throws ServletException, IOException {
		HttpServletRequest request = context.getRequest();
		HttpServletResponse response = context.getResponse();

		if (!checkConfiguration(response)) {
			return;
		}

		List<?> parameters = extractParameterList(request);

		String orgName = extractParameter("organisationName", parameters);
		String orgUrl = extractParameter("organisationUrl", parameters);
		String email = extractParameter("email", parameters);
		String phone = extractParameter("phone", parameters);
		String givenName = extractParameter("givenName", parameters);
		String surName = extractParameter("surName", parameters);
		String entityId = extractParameter("entityId", parameters);
		final String password = extractParameter("keystorePassword", parameters);
		byte[] metadata = extractFile("metadata", parameters).get();
		FileItem ksData = extractFile("keystore", parameters);
		byte[] keystore = null;
		
		if (ksData != null) {
			keystore = ksData.get();
		}

		if (!checkNotNull(orgName, orgUrl, email, phone, givenName, surName, password, metadata, entityId) || metadata.length == 0 || (keystore == null && !Boolean.valueOf(extractParameter("createkeystore", parameters)))) {
			Map<String, Object> params = getStandardParameters(request);
			params.put("error", "All fields must be filled.");
			params.put("organisationName", orgName);
			params.put("organisationUrl", orgUrl);
			params.put("email", email);
			params.put("phone", phone);
			params.put("givenName", givenName);
			params.put("surName", surName);
			params.put("keystorePassword", password);
			params.put("entityId", entityId);
			log.info("Parameters not correct: " + params);
			log.info("Metadata: " + new String(metadata));

			String res = renderTemplate("configure.vm", params, true);
			sendResponse(response, res);
			return;
		}

		Credential credential = context.getCredential();
		if (keystore != null && keystore.length > 0) {
			ByteArrayInputStream byteArrayInputStream = null;
			try {
				byteArrayInputStream = new ByteArrayInputStream(keystore);

				KeyStore ks = KeyStore.getInstance("JKS");
				ks.load(byteArrayInputStream, password.toCharArray());
				credential = CredentialRepository.createCredential(ks, password);
			}
			catch (Exception e) {
				log.info("Keystore is not of type JKS. Trying type PKCS12");
				try {
					KeyStore ks = KeyStore.getInstance("PKCS12");
					byteArrayInputStream.reset();
					ks.load(byteArrayInputStream, password.toCharArray());
					credential = CredentialRepository.createCredential(ks, password);
				}
				catch (Exception e2) {
					log.error("Unable to use/load keystore", e2);
					throw new RuntimeException("Unable to use/load keystore", e2);
				}
			}
			finally {
				if (byteArrayInputStream != null)
					byteArrayInputStream.close();
			}
		}
		else if (Boolean.valueOf(extractParameter("createkeystore", parameters))) {
			try {
				BasicX509Credential cred = new BasicX509Credential();
				KeyPair kp = dk.itst.oiosaml.security.SecurityHelper.generateKeyPairFromURI("http://www.w3.org/2001/04/xmlenc#rsa-1_5", 1024);
				cred.setPrivateKey(kp.getPrivate());
				cred.setPublicKey(kp.getPublic());
				credential = cred;

				KeyStore ks = KeyStore.getInstance("JKS");
				ks.load(null, null);
				X509Certificate cert = dk.itst.oiosaml.security.SecurityHelper.generateCertificate(credential, getEntityId(request));
				cred.setEntityCertificate(cert);

				ks.setKeyEntry("oiosaml", credential.getPrivateKey(), password.toCharArray(), new Certificate[] { cert });
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				ks.store(bos, password.toCharArray());

				keystore = bos.toByteArray();
				bos.close();
			}
			catch (Exception e) {
				log.error("Unable to generate credential", e);
				throw new RuntimeException("Unable to generate credential", e);
			}
		}

		EntityDescriptor descriptor = generateSPDescriptor(
				getBaseUrl(request),
				entityId,
				credential,
				orgName,
				orgUrl,
				email,
				phone,
				givenName,
				surName,
				Boolean.valueOf(extractParameter("enableArtifact", parameters)),
				Boolean.valueOf(extractParameter("enablePost", parameters)),
				Boolean.valueOf(extractParameter("enableSoap", parameters)),
				Boolean.valueOf(extractParameter("enablePostSLO", parameters)),
				Boolean.valueOf(extractParameter("supportOCESAttributeProfile", parameters)),
				Boolean.valueOf(extractParameter("enableEID", parameters)),
				Boolean.valueOf(extractParameter("enableEIDNaturalPerson", parameters)),
				Boolean.valueOf(extractParameter("enableEIDLegalPerson", parameters)));

		File zipFile = generateZipFile(request.getContextPath(), password, metadata, keystore, descriptor, Boolean.valueOf(extractParameter("enableEID", parameters)));

		byte[] configurationContents = saveConfigurationInSession(request, zipFile);
		boolean written = writeConfiguration(getHome(), configurationContents);

		Map<String, Object> params = new HashMap<String, Object>();
		params.put("home", getHome());
		params.put("written", written);
		sendResponse(response, renderTemplate("done.vm", params, true));
	}

	public boolean writeConfiguration(String homeDir, byte[] configurationContents) {
		File root = new File(homeDir);
		if (!root.isDirectory() || !root.canWrite()) {
			return false;
		}
		boolean written = true;
		try {
			ZipInputStream input = new ZipInputStream(new ByteArrayInputStream(configurationContents));
			ZipEntry next = null;
			while ((next = input.getNextEntry()) != null) {
				File newFile = new File(root, next.getName());
				FileUtils.forceMkdir(newFile.getParentFile());

				FileOutputStream file = new FileOutputStream(newFile);
				IOUtils.copy(input, file);
				file.close();
				input.closeEntry();
			}
			input.close();
		}
		catch (IOException e) {
			log.error("Unable to write configuration files to " + root, e);
			written = false;
		}
		return written;
	}

	private static byte[] saveConfigurationInSession(final HttpServletRequest request, File zipFile) throws IOException, FileNotFoundException {
		byte[] configurationContents = IOUtils.toByteArray(new FileInputStream(zipFile));
		request.getSession().setAttribute(SESSION_CONFIGURATION, configurationContents);
		return configurationContents;
	}

	@SuppressWarnings("serial")
	protected File generateZipFile(final String contextPath, final String password, byte[] idpMetadata, byte[] keystore, EntityDescriptor descriptor, final boolean enableEID) throws IOException {
		File zipFile = File.createTempFile("oiosaml-", ".zip");
		ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFile));
		zos.putNextEntry(new ZipEntry(SAMLUtil.OIOSAML_DEFAULT_CONFIGURATION_FILE));
		zos.write(renderTemplate("defaultproperties.vm", new HashMap<String, Object>() {
			{
				put("homename", Constants.PROP_HOME);
				put("servletPath", contextPath);
				put("password", password);
				put("enableEID", enableEID);
			}
		}, false).getBytes());
		zos.closeEntry();

		zos.putNextEntry(new ZipEntry("metadata/SP/SPMetadata.xml"));
		zos.write(SAMLUtil.getSAMLObjectAsPrettyPrintXML(descriptor).getBytes());
		zos.closeEntry();

		zos.putNextEntry(new ZipEntry("metadata/IdP/IdPMetadata.xml"));
		zos.write(idpMetadata);
		zos.closeEntry();

		zos.putNextEntry(new ZipEntry("certificate/keystore"));
		zos.write(keystore);
		zos.closeEntry();

		zos.putNextEntry(new ZipEntry("oiosaml-sp.log4j.xml"));
		IOUtils.copy(getClass().getResourceAsStream("/oiosaml-sp.log4j.xml"), zos);
		zos.closeEntry();

		zos.close();
		return zipFile;
	}

	protected EntityDescriptor generateSPDescriptor(String baseUrl, String entityId, Credential credential, String orgName, String orgUrl, String email, String phone, String givenName, String surName, boolean enableArtifact, boolean enableRedirect, boolean enableSoap, boolean enablePostSLO, boolean supportOCESAttributes, boolean enableEID, boolean enableEIDNaturalPerson, boolean enableEIDLegalPerson) {
		EntityDescriptor descriptor = SAMLUtil.buildXMLObject(EntityDescriptor.class);
		descriptor.setEntityID(entityId);

		SPSSODescriptor spDescriptor = SAMLUtil.buildXMLObject(SPSSODescriptor.class);
		spDescriptor.setAuthnRequestsSigned(true);
		spDescriptor.setWantAssertionsSigned(true);

		ContactPerson contact = SAMLUtil.buildXMLObject(ContactPerson.class);
		contact.getEmailAddresses().add(SAMLUtil.createEmail(email));
		contact.setCompany(SAMLUtil.createCompany(orgName));
		contact.setType(ContactPersonTypeEnumeration.TECHNICAL);
		contact.setSurName(SAMLUtil.createSurName(surName));
		contact.setGivenName(SAMLUtil.createGivenName(givenName));
		contact.getTelephoneNumbers().add(SAMLUtil.createTelephoneNumber(phone));
		descriptor.getContactPersons().add(contact);
		
		if (enableEID) {
			ContactPerson admContact = SAMLUtil.buildXMLObject(ContactPerson.class);
			admContact.getEmailAddresses().add(SAMLUtil.createEmail(email));
			admContact.setCompany(SAMLUtil.createCompany(orgName));
			admContact.setType(ContactPersonTypeEnumeration.ADMINISTRATIVE);
			admContact.setSurName(SAMLUtil.createSurName(surName));
			admContact.setGivenName(SAMLUtil.createGivenName(givenName));
			admContact.getTelephoneNumbers().add(SAMLUtil.createTelephoneNumber(phone));
			descriptor.getContactPersons().add(admContact);			
		}
		
		descriptor.setOrganization(SAMLUtil.createOrganization(orgName, orgName, orgUrl));

		KeyDescriptor signingDescriptor = SAMLUtil.buildXMLObject(KeyDescriptor.class);
		signingDescriptor.setUse(UsageType.SIGNING);
		KeyDescriptor encryptionDescriptor = SAMLUtil.buildXMLObject(KeyDescriptor.class);
		encryptionDescriptor.setUse(UsageType.ENCRYPTION);

		try {
			KeyInfoGenerator gen = SecurityHelper.getKeyInfoGenerator(credential, org.opensaml.xml.Configuration.getGlobalSecurityConfiguration(), null);
			signingDescriptor.setKeyInfo(gen.generate(credential));
			encryptionDescriptor.setKeyInfo(gen.generate(credential));
		}
		catch (SecurityException e1) {
			throw new WrappedException(Layer.BUSINESS, e1);
		}
		spDescriptor.getKeyDescriptors().add(signingDescriptor);
		spDescriptor.getKeyDescriptors().add(encryptionDescriptor);

		spDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		spDescriptor.getAssertionConsumerServices().add(SAMLUtil.createAssertionConsumerService(baseUrl + "/SAMLAssertionConsumer", SAMLConstants.SAML2_POST_BINDING_URI, 0, true));
		if (enableArtifact) {
			spDescriptor.getAssertionConsumerServices().add(SAMLUtil.createAssertionConsumerService(baseUrl + "/SAMLAssertionConsumer", SAMLConstants.SAML2_ARTIFACT_BINDING_URI, 1, false));
		}
		if (enableRedirect) {
			spDescriptor.getAssertionConsumerServices().add(SAMLUtil.createAssertionConsumerService(baseUrl + "/SAMLAssertionConsumer", SAMLConstants.SAML2_REDIRECT_BINDING_URI, 2, false));
		}

		spDescriptor.getSingleLogoutServices().add(SAMLUtil.createSingleLogoutService(baseUrl + "/LogoutServiceHTTPRedirect", baseUrl + "/LogoutServiceHTTPRedirectResponse", SAMLConstants.SAML2_REDIRECT_BINDING_URI));

		if (enableSoap) {
			spDescriptor.getSingleLogoutServices().add(SAMLUtil.createSingleLogoutService(baseUrl + "/LogoutServiceSOAP", null, SAMLConstants.SAML2_SOAP11_BINDING_URI));
		}

		if (enablePostSLO) {
			spDescriptor.getSingleLogoutServices().add(SAMLUtil.createSingleLogoutService(baseUrl + "/LogoutServiceHTTPPost", baseUrl + "/LogoutServiceHTTPRedirectResponse", SAMLConstants.SAML2_POST_BINDING_URI));
		}

		if (enableEID) {
			NameIDFormat persistentNameIDFormat = SAMLUtil.createNameIDFormat(OIOSAMLConstants.PERSISTENT);
			List<NameIDFormat> nameIDFormats = spDescriptor.getNameIDFormats();
			nameIDFormats.add(persistentNameIDFormat);
		}
		else {
			NameIDFormat x509SubjectNameIDFormat = SAMLUtil.createNameIDFormat(OIOSAMLConstants.NAMEIDFORMAT_X509SUBJECTNAME);
			List<NameIDFormat> nameIDFormats = spDescriptor.getNameIDFormats();
			nameIDFormats.add(x509SubjectNameIDFormat);
		}

		if (enableArtifact) {
			spDescriptor.getArtifactResolutionServices().add(SAMLUtil.createArtifactResolutionService(baseUrl + "/SAMLAssertionConsumer"));
		}

		if (supportOCESAttributes || (enableEID && enableEIDLegalPerson) || (enableEID && enableEIDNaturalPerson)) {
			addAttributeConsumerService(spDescriptor, entityId, supportOCESAttributes, enableEIDLegalPerson, enableEIDNaturalPerson);
		}

		descriptor.getRoleDescriptors().add(spDescriptor);
		return descriptor;
	}

	private static void addAttributeConsumerService(SPSSODescriptor spDescriptor, String serviceName, boolean supportOCESAttributes, boolean enableEIDLegalPerson, boolean enableEIDNaturalPerson) {
		AttributeConsumingService service = SAMLUtil.createAttributeConsumingService(serviceName);

		if (supportOCESAttributes) {
			String[] required = { OIOSAMLConstants.ATTRIBUTE_SURNAME_NAME, OIOSAMLConstants.ATTRIBUTE_COMMON_NAME_NAME, OIOSAMLConstants.ATTRIBUTE_UID_NAME, OIOSAMLConstants.ATTRIBUTE_MAIL_NAME, OIOSAMLConstants.ATTRIBUTE_ASSURANCE_LEVEL_NAME, OIOSAMLConstants.ATTRIBUTE_SPECVER_NAME,
					OIOSAMLConstants.ATTRIBUTE_SERIAL_NUMBER_NAME, OIOSAMLConstants.ATTRIBUTE_YOUTH_CERTIFICATE_NAME, OIOSAMLConstants.ATTRIBUTE_CERTIFICATE_ISSUER, };
	
			String[] optional = { OIOSAMLConstants.ATTRIBUTE_UNIQUE_ACCOUNT_KEY_NAME, OIOSAMLConstants.ATTRIBUTE_CVR_NUMBER_IDENTIFIER_NAME, OIOSAMLConstants.ATTRIBUTE_ORGANISATION_NAME_NAME, OIOSAMLConstants.ATTRIBUTE_ORGANISATION_UNIT_NAME, OIOSAMLConstants.ATTRIBUTE_TITLE_NAME,
					OIOSAMLConstants.ATTRIBUTE_POSTAL_ADDRESS_NAME, OIOSAMLConstants.ATTRIBUTE_PSEUDONYM_NAME, OIOSAMLConstants.ATTRIBUTE_USER_CERTIFICATE_NAME, OIOSAMLConstants.ATTRIBUTE_PID_NUMBER_IDENTIFIER_NAME, OIOSAMLConstants.ATTRIBUTE_CPR_NUMBER_NAME,
					OIOSAMLConstants.ATTRIBUTE_RID_NUMBER_IDENTIFIER_NAME, OIOSAMLConstants.ATTRIBUTE_PRIVILEGES_INTERMEDIATE, OIOSAMLConstants.ATTRIBUTE_USER_ADMINISTRATOR_INDICATOR };
	
			for (String attr : required) {
				service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute(attr, OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, true));
			}
	
			for (String attr : optional) {
				service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute(attr, OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			}
		}
		
		if (enableEIDLegalPerson) {
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:legalperson:LegalPersonIdentifier", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, true));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:legalperson:LegalName", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, true));
			
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:legalperson:LegalPersonAddress", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:legalperson:VATRegistrationNumber", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:legalperson:TaxReference", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:legalperson:D-2012-17-EUIdentifier", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:legalperson:LEI", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:legalperson:EORI", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:legalperson:SEED", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:legalperson:SIC", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
		}
		
		if (enableEIDNaturalPerson) {
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:naturalperson:PersonIdentifier", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, true));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:naturalperson:CurrentFamilyName", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, true));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:naturalperson:CurrentGivenName", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, true));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:naturalperson:DateOfBirth", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, true));

			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:naturalperson:BirthName", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:naturalperson:PlaceOfBirth", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:naturalperson:CurrentAddress", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
			service.getRequestAttributes().add(SAMLUtil.createRequestedAttribute("dk:gov:saml:attribute:eidas:naturalperson:Gender", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT, false));
		}

		spDescriptor.getAttributeConsumingServices().add(service);
	}

	private static List<?> extractParameterList(final HttpServletRequest request) {
		List<?> parameters;
		try {
			FileItemFactory itemFactory = new DiskFileItemFactory();
			parameters = new ServletFileUpload(itemFactory).parseRequest(request);
		}
		catch (FileUploadException e) {
			log.error("Unable to parse uploaded files", e);
			throw new RuntimeException("Unable to parse uploaded files", e);
		}
		return parameters;
	}

	@SuppressWarnings("serial")
	private boolean checkConfiguration(HttpServletResponse response) throws IOException {
		if (isConfigured()) {
			sendResponse(response, renderTemplate("alreadyConfigured.vm", new HashMap<String, Object>() {
				{
					put("home", getHome());
				}
			}, true));
			return false;
		}
		return true;
	}

	private static FileItem extractFile(String name, List<?> files) {
		for (Iterator<?> i = files.iterator(); i.hasNext();) {
			FileItem file = (FileItem) i.next();
			if (!file.isFormField() && file.getFieldName().equals(name)) {
				return file;
			}
		}
		return null;
	}

	private static String extractParameter(String name, List<?> files) {
		for (Iterator<?> i = files.iterator(); i.hasNext();) {
			FileItem file = (FileItem) i.next();
			if (file.isFormField() && file.getFieldName().equals(name)) {
				return "".equals(file.getString()) ? null : file.getString();
			}
		}
		return null;
	}

	private static void sendResponse(HttpServletResponse response, String res) throws IOException {
		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(res);
	}

	protected String getBaseUrl(HttpServletRequest request) {
		String url = request.getRequestURL().toString();
		int idx = url.lastIndexOf(request.getServletPath());

		return url.substring(0, idx + request.getServletPath().length());
	}

	protected boolean isHomeAvailable() {
		String home = getHome();
		if (home == null)
			return false;

		if (new File(home).isDirectory()) {
			return true;
		}

		return false;
	}

	protected boolean isConfigured() {
		String home = getHome();
		if (home == null)
			return false;

		File homeDir = new File(home);
		String[] files = homeDir.list();
		if (files != null && files.length > 0) {
			return true;
		}
		
		return false;
	}

	protected String renderTemplate(String template, Map<String, Object> objects, boolean html) {
		VelocityContext ctx = new VelocityContext();
		for (Map.Entry<String, Object> e : objects.entrySet()) {
			ctx.put(e.getKey(), e.getValue());
		}

		StringWriter w = new StringWriter();

		try {
			if (html) {
				engine.mergeTemplate("head.vm", "UTF-8", ctx, w);
			}
			engine.mergeTemplate(template, "UTF-8", ctx, w);
			if (html) {
				engine.mergeTemplate("foot.vm", "UTF-8", ctx, w);
			}
		}
		catch (Exception e) {
			log.error("Unable to merge templates", e);
		}
		return w.toString();
	}

	private static String getHome() {
		String pathToHomeDir = ((FileConfiguration) SAMLConfigurationFactory.getConfiguration()).getHomeDir();
		File homeDir = new File(pathToHomeDir);
		if (!homeDir.exists())
			homeDir.mkdir();
		return pathToHomeDir;
	}

	private static String getEntityId(HttpServletRequest request) {
		return request.getScheme() + "://saml." + request.getServerName();
	}

	private static boolean checkNotNull(Object... objs) {
		for (Object o : objs) {
			if (o == null) {
				return false;
			}
		}
		return true;
	}

	protected Map<String, Object> getStandardParameters(HttpServletRequest request) {
		String base = getBaseUrl(request);
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("artifactResponseUrl", base + "/SAMLAssertionConsumer");
		params.put("postResponseUrl", base + "/SAMLAssertionConsumer");
		params.put("logoutUrl", base + "/SAMLAssertionConsumer");
		params.put("logoutResponseUrl", base + "/LogoutServiceHTTPRedirectResponse");
		params.put("logoutRequestUrl", base + "/LogoutServiceHTTPRedirect");
		params.put("logoutSoapRequestUrl", base + "/LogoutServiceSOAP");
		params.put("logoutPostRequestUrl", base + "/LogoutServiceHTTPPost");
		params.put("home", getHome());
		params.put("entityId", getEntityId(request));
		return params;
	}

}
