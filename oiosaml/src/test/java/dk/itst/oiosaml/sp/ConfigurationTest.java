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
package dk.itst.oiosaml.sp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.webapp.WebAppContext;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebAssert;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput;
import com.gargoylesoftware.htmlunit.html.HtmlFileInput;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.service.util.Constants;

public class ConfigurationTest {
	protected static final String BASE = "http://127.0.0.1:8808/saml";
	private Server server;
	private File tmpdir;
	private WebClient client;
	private HtmlPage page;

	@Before
	public void setUp() throws Exception {
		tmpdir = new File(System.getProperty("java.io.tmpdir") + "/oiosaml-" + Math.random());
		if (tmpdir.exists()) {
			FileUtils.cleanDirectory(tmpdir);
		}
		tmpdir.mkdir();

		// Reinitialize SAMLConfiguration
        Map<String,String> params=new HashMap<String, String>();
        params.put(Constants.INIT_OIOSAML_HOME, tmpdir.getAbsolutePath());
        SAMLConfigurationFactory.getConfiguration().setInitConfiguration(params);
		
		//FileConfiguration.setSystemConfiguration(null);
		IdpMetadata.setMetadata(null);
		SPMetadata.setMetadata(null);
		System.setProperty(SAMLUtil.OIOSAML_HOME, tmpdir.getAbsolutePath());
		
		server = new Server(8808);
		WebAppContext wac = new WebAppContext();
		wac.setClassLoader(Thread.currentThread().getContextClassLoader());
		wac.setContextPath("/saml");
		wac.setWar("src/test/resources/webapp/");
		System.out.println(wac);

		server.setHandler(wac);
		server.start();
		
		client = new WebClient();
		page = (HtmlPage) client.getPage(BASE + "/saml/configure");
	}
	
	@After
	public void tearDown() throws Exception {
		if (server != null) {
			server.stop();
		}
		
		if (tmpdir != null) {
			FileUtils.deleteDirectory(tmpdir);
		}
	}
	
	@Test
	public void testNotConfigured() throws Exception {
		assertNotNull(page.getFormByName("configure"));
	}
	
	@Test
	public void testMissingFields() throws Exception {
		HtmlForm form = page.getFormByName("configure");
		form.getInputByName("email").setValueAttribute("jre@trifork.com");
		
		HtmlPage configure = (HtmlPage) form.getInputByValue("Configure system").click();
		assertEquals(200, configure.getWebResponse().getStatusCode());
		form = configure.getFormByName("configure");
		assertNotNull(form);
		assertNotNull(form.getInputByName("email"));
		assertEquals("jre@trifork.com", form.getInputByName("email").getValueAttribute());
		
	}
	
	@Test
	public void testConfigure() throws Exception {
		HtmlForm form = page.getFormByName("configure");
		form.getInputByName("createkeystore").setValueAttribute("true");
		HtmlCheckBoxInput cb = (HtmlCheckBoxInput) form.getInputByName("createkeystore");
		cb.setChecked(true);
		form.getInputByName("keystorePassword").setValueAttribute("testing");
		form.getInputByName("organisationName").setValueAttribute("Trifork");
		form.getInputByName("organisationUrl").setValueAttribute("http://www.trifork.com");
		form.getInputByName("email").setValueAttribute("jre@trifork.com");
		form.getInputByName("phone").setValueAttribute("jre@trifork.com");
		form.getInputByName("givenName").setValueAttribute("Joachim");
		form.getInputByName("surName").setValueAttribute("Recht");
		form.getInputByName("enableArtifact").setValueAttribute("true");
		cb = (HtmlCheckBoxInput) form.getInputByName("enableArtifact");
		cb.setChecked(true);
		form.getInputByName("enableRedirect").setValueAttribute("true");
		cb = (HtmlCheckBoxInput) form.getInputByName("enableRedirect");
		cb.setChecked(true);
		
		HtmlFileInput file = (HtmlFileInput) form.getInputByName("metadata");
		file.setContentType("text/xml");
		file.setValueAttribute(getClass().getResource("/IdPMetadata.xml").getFile());

		HtmlPage configured = (HtmlPage) form.getInputByValue("Configure system").click();
		
		assertEquals(200, configured.getWebResponse().getStatusCode());
		assertEquals(0, configured.getForms().size());
		
		HtmlAnchor dl = configured.getAnchorByHref("configure?download");
		assertNotNull(dl);
		Page downloaded = dl.click();
		assertEquals(200, downloaded.getWebResponse().getStatusCode());
		assertEquals("application/octet-stream", downloaded.getWebResponse().getContentType());
		
		HtmlPage alreadyConfigured = (HtmlPage) client.getPage(BASE + "/saml/configure");
		assertEquals(0, alreadyConfigured.getForms().size());
		
		// other clients shouldn't be able to download
		client.setCookiesEnabled(false);
		client.setThrowExceptionOnFailingStatusCode(false);
		Page noaccess = client.getPage(BASE + "/saml/configure?download");
		assertEquals(404, noaccess.getWebResponse().getStatusCode());
		
		
		HtmlPage home = (HtmlPage) client.getPage(BASE);
		WebAssert.assertLinkNotPresentWithText(home, "configure");
	}
}
