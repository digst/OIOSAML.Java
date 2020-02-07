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
package dk.itst.oiosaml.sp;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.io.FileUtils;
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
import org.junit.BeforeClass;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.webapp.WebAppContext;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.RefreshHandler;
import com.gargoylesoftware.htmlunit.SubmitMethod;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequestSettings;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.model.OIOResponse;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.session.SingleVMSessionHandlerFactory;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.AttributeUtil;

@SuppressWarnings("deprecation")
public abstract class IntegrationTests {
	protected static final String BASE = "http://127.0.0.1:8808/saml";
	protected RedirectRefreshHandler handler;
	private File tmpdir;
	protected BasicX509Credential credential;
	protected SPMetadata spMetadata;
	protected IdpMetadata idpMetadata;
	protected WebClient client;
	private Server server;

	@BeforeClass
	public static void configure() throws Exception {
		DefaultBootstrap.bootstrap();
	}
	
	@Before
	public final void setUpServer() throws Exception {
		tmpdir = new File(System.getProperty("java.io.tmpdir") + "/oiosaml-" + Math.random());
		tmpdir.mkdir();

        // Reinitialize SAMLConfiguration
        Map<String,String> params=new HashMap<String, String>();
        params.put(Constants.INIT_OIOSAML_HOME, tmpdir.getAbsolutePath());
        SAMLConfigurationFactory.getConfiguration().setInitConfiguration(params);

        FileUtils.forceMkdir(new File(tmpdir, "metadata/IdP"));
		FileUtils.forceMkdir(new File(tmpdir, "metadata/SP"));
		
		credential = TestHelper.getCredential();
		EntityDescriptor idpDescriptor = TestHelper.buildEntityDescriptor(credential);
		FileOutputStream fos = new FileOutputStream(new File(tmpdir, "metadata/IdP/gen.xml"));
		IOUtils.write(XMLHelper.nodeToString(SAMLUtil.marshallObject(idpDescriptor)).getBytes(), fos);
		fos.close();
		
		EntityDescriptor spDescriptor = (EntityDescriptor) SAMLUtil.unmarshallElement(getClass().getResourceAsStream("/SPMetadata.xml"));
		fos = new FileOutputStream(new File(tmpdir, "metadata/SP/SPMetadata.xml"));
		IOUtils.write(XMLHelper.nodeToString(SAMLUtil.marshallObject(spDescriptor)).getBytes(), fos);
		fos.close();
		
		spMetadata = new SPMetadata(spDescriptor, SAMLConstants.SAML20P_NS);
		idpMetadata = new IdpMetadata(SAMLConstants.SAML20P_NS, idpDescriptor);
		
		fos = new FileOutputStream(new File(tmpdir, "oiosaml-sp.log4j.xml"));
		IOUtils.write("<!DOCTYPE log4j:configuration SYSTEM \"http://logging.apache.org/log4j/docs/api/org/apache/log4j/xml/log4j.dtd\"><log4j:configuration xmlns:log4j=\"http://jakarta.apache.org/log4j/\" debug=\"false\"></log4j:configuration>", fos);
		fos.close();

        final File crlFile = generateCRL(null);

		Properties props = new Properties();
        props.setProperty(Constants.PROP_SHOW_ERROR, "true");
		props.setProperty(Constants.PROP_CERTIFICATE_LOCATION, "keystore");
		props.setProperty(Constants.PROP_CERTIFICATE_PASSWORD, "password");
		props.setProperty(Constants.PROP_LOG_FILE_NAME, "oiosaml-sp.log4j.xml");
		props.setProperty(Constants.PROP_SESSION_HANDLER_FACTORY, SingleVMSessionHandlerFactory.class.getName());
		props.setProperty(Constants.PROP_CRL + idpMetadata.getFirstMetadata().getEntityID(), crlFile.toURI().toString());

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null, null);
		ks.setKeyEntry("oiosaml", credential.getPrivateKey(), "password".toCharArray(), new Certificate[] { 
			TestHelper.getCertificate(credential) });
		OutputStream bos = new FileOutputStream(new File(tmpdir, "keystore"));
		ks.store(bos, "password".toCharArray());
		bos.close();

		props.setProperty(Constants.PROP_ASSURANCE_LEVEL, "2");
		props.setProperty(Constants.PROP_IGNORE_CERTPATH, "true");
		fos = new FileOutputStream(new File(tmpdir, SAMLUtil.OIOSAML_DEFAULT_CONFIGURATION_FILE));
		props.store(fos, "Generated");
		fos.close();

		IdpMetadata.setMetadata(null);
		SPMetadata.setMetadata(null);
		server = new Server(8808);
		WebAppContext wac = new WebAppContext();
		wac.setClassLoader(Thread.currentThread().getContextClassLoader());
		wac.setContextPath("/saml");
		wac.setWar("src/test/resources/webapp/");

		server.setHandler(wac);
		server.start();

        Thread.sleep(1000); // This sleep is necessary to ensure that CRLChecker finishes before the first request. Otherwise, no certificates will be valid.
		
		client = new WebClient();
		client.setRedirectEnabled(false);
		client.setThrowExceptionOnFailingStatusCode(false);
		handler = new RedirectRefreshHandler();
		client.setRefreshHandler(handler);
	}
	
	@After
	public final void tearDownServer() throws Exception {
		if (server != null) {
			server.stop();
		}
		if (tmpdir != null) {
            FileUtils.deleteDirectory(tmpdir);
		}
	}

	protected static class RedirectRefreshHandler implements RefreshHandler {
		protected URL url;
		
		public void handleRefresh(Page arg0, URL arg1, int arg2) throws IOException {
			url = arg1;
		}
	}

	protected WebRequestSettings buildResponse(String status, int assuranceLevel) throws Exception {
		Document document = TestHelper.parseBase64Encoded(Utils.getParameter("SAMLRequest", handler.url.toString()));
		AuthnRequest ar = (AuthnRequest) Configuration.getUnmarshallerFactory().getUnmarshaller(document.getDocumentElement()).unmarshall(document.getDocumentElement());
		
		Assertion assertion = TestHelper.buildAssertion(spMetadata.getDefaultAssertionConsumerService().getLocation(), spMetadata.getEntityID());
		
		assertion.getAttributeStatements().get(0).getAttributes().clear();
		assertion.getAttributeStatements().get(0).getAttributes().add(AttributeUtil.createAssuranceLevel(assuranceLevel));

		// sign assertion
		Signature signature = SAMLUtil.buildXMLObject(Signature.class);
	    signature.setSigningCredential(credential);
        SecurityHelper.prepareSignatureParams(signature, credential, null, null);
        assertion.setSignature(signature);
	    SAMLUtil.marshallObject(assertion);
        Signer.signObject(signature);
		
		Response r = TestHelper.buildResponse(assertion);
		r.setStatus(SAMLUtil.createStatus(status));
		r.setInResponseTo(ar.getID());
		OIOResponse response = new OIOResponse(r);

		
		WebRequestSettings req = new WebRequestSettings(new URL(BASE + "/saml/SAMLAssertionConsumer"), SubmitMethod.POST);
		req.setRequestParameters(Arrays.asList(
				new NameValuePair("SAMLResponse", response.toBase64()),
				new NameValuePair("RelayState", Utils.getParameter("RelayState", handler.url.toString()))));
		return req;
	}

    private File generateCRL(X509Certificate cert) throws CRLException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, OperatorCreationException {
        X500Name issuer = new X500Name("CN=ca");
        Date thisUpdate = new Date();
        X509v2CRLBuilder gen = new X509v2CRLBuilder(issuer, thisUpdate);
        gen.setNextUpdate(new Date(System.currentTimeMillis() + 60000));

        if (cert != null) {
            gen.addCRLEntry(cert.getSerialNumber(), new Date(System.currentTimeMillis() - 1000), CRLReason.keyCompromise);
        }

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(credential.getPrivateKey());
        X509CRLHolder crl = gen.build(sigGen);

        final File crlFile = File.createTempFile("test", "test");
        crlFile.deleteOnExit();
        FileOutputStream fos = new FileOutputStream(crlFile);
        IOUtils.write(crl.getEncoded(), fos);
        fos.close();
        return crlFile;
    }
}
