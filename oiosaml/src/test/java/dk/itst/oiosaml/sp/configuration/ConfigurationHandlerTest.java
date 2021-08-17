package dk.itst.oiosaml.sp.configuration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.FileUtils;
import org.jmock.Expectations;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.RequestContext;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.Constants;

public class ConfigurationHandlerTest extends AbstractServiceTests {
	
	private ConfigurationHandler handler;
	private File homeDir;

	@Before
	public void setUp() throws Exception{
		handler = new ConfigurationHandler();
		homeDir = new File(File.createTempFile("test", "test").getAbsolutePath() + ".home");
		homeDir.mkdir();
	}
	
	@After
	public void tearDown() throws Exception{
		if (homeDir != null) {
			FileUtils.forceDelete(homeDir);
		}
	}

	@Test
	public void testIsConfigured() throws Exception{
        // Reinitialize SAMLConfiguration
        Map<String,String> params=new HashMap<String, String>();
        params.put(Constants.INIT_OIOSAML_HOME, homeDir.getAbsolutePath());
        SAMLConfigurationFactory.getConfiguration().setInitConfiguration(params);

		assertTrue(handler.isHomeAvailable());
		assertFalse(handler.isConfigured());
		
		File content = new File(homeDir, "content");
		FileOutputStream fos = new FileOutputStream(content);
		fos.write("testing".getBytes());
		fos.close();
		
		assertTrue(handler.isHomeAvailable());
		assertTrue(handler.isConfigured());
	}
	
	@Test
	public void testRender() {
		String res = handler.renderTemplate("alreadyConfigured.vm", new HashMap<String, Object>() {{
			put("home", "testingtesting");
		}}, true);
		assertTrue(res.indexOf("testingtesting") > -1);
	}
	
	@Test
	public void testGetBaseUrl() {
		context.checking(new Expectations() {{
			allowing(req).getServletPath(); will(returnValue("/saml"));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer("http://localhost:89/saml/configure")));
		}});
		assertEquals("http://localhost:89/saml", handler.getBaseUrl(req));
	}

	@Test 
	public void downloadFailWhenNoConfiguration() throws Exception {
		context.checking(new Expectations() {{
			one(req).getParameter("download"); will(returnValue(""));
			one(session).getAttribute(ConfigurationHandler.SESSION_CONFIGURATION); will(returnValue(null));
			one(res).sendError(with(equal(HttpServletResponse.SC_NOT_FOUND)), with(any(String.class)));
		}});
		handler.handleGet(new RequestContext(req, res, null, null, null, null, null, bindingHandlerFactory));
	}
	
	@Test
	public void testDownloadConfiguration() throws Exception{
		final ByteArrayOutputStream os = new ByteArrayOutputStream();
		context.checking(new Expectations() {{
			one(req).getParameter("download"); will(returnValue(""));
			one(session).getAttribute(ConfigurationHandler.SESSION_CONFIGURATION); will(returnValue("testing".getBytes()));
			one(res).setContentType("application/octet-stream");
			one(res).setContentLength("testing".length());
			one(res).addHeader(with(equal("Content-disposition")), with(any(String.class)));
			one(res).getOutputStream(); will(returnValue(TestHelper.createOutputStream(os)));
		}});
		handler.handleGet(new RequestContext(req, res, null, null, null, null, null, bindingHandlerFactory));
		
		assertEquals("testing", new String(os.toByteArray()));
	}
	
	@Test
	public void showConfigurationIfUnconfigured() throws Exception {
		Map<String,String> params=new HashMap<String, String>();
		params.put(Constants.INIT_OIOSAML_HOME, homeDir.getAbsolutePath());
		SAMLConfigurationFactory.getConfiguration().setInitConfiguration(params);

		final StringWriter sw = new StringWriter();
		final String url = "http://localhost/saml";
		context.checking(new Expectations() {{
			one(req).getParameter(with(any(String.class))); will(returnValue(null));
			one(res).setContentType("text/html");
			one(res).setCharacterEncoding("UTF-8");
			one(res).getWriter(); will(returnValue(new PrintWriter(sw)));
			allowing(req).getRequestURL(); will(returnValue(new StringBuffer(url)));
			allowing(req).getServletPath(); will(returnValue("/saml"));
			allowing(req).getServerName(); will(returnValue("localhost"));
			allowing(req).getScheme(); will(returnValue("http"));
		}});

		handler.handleGet(new RequestContext(req, res, null, null, null, null, null, bindingHandlerFactory));
		String output = sw.toString();
		assertNotNull(output);
		assertTrue(output.indexOf(url) > -1);
		
		// entity id should be displayed
		assertTrue(output.indexOf("saml.localhost") > -1);
	}

	@Test
	public void testGenerateSPDescriptor() {
		EntityDescriptor d = handler.generateSPDescriptor("http://localhost",
				"entityId", credential, "orgName", "orgUrl", "email",
				"phone", "givenName", "surName",
				true, true, true, true, false,
				false, false, false);
		assertEquals("entityId", d.getEntityID());
		assertEquals(1, d.getContactPersons().size());
		assertNotNull(d.getOrganization());
		assertNotNull(d.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
		assertEquals(0, d.getSPSSODescriptor(SAMLConstants.SAML20P_NS).getAttributeConsumingServices().size());
	}
	
	@Test
	public void testGenerateSPDescriptorWithAttributes() {
		EntityDescriptor d = handler.generateSPDescriptor("http://localhost", "entityId", credential, "orgName", "orgUrl", "email",
				"phone", "givenName", "surName",
				true, true, true, true, true,
				false, false, false);
		assertEquals(1, d.getSPSSODescriptor(SAMLConstants.SAML20P_NS).getAttributeConsumingServices().size());
		assertEquals(22, d.getSPSSODescriptor(SAMLConstants.SAML20P_NS).getAttributeConsumingServices().get(0).getRequestAttributes().size());
	}
	
	
	@Test
	public void testWriteConfiguration() throws Exception {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		ZipOutputStream zos = new ZipOutputStream(os);
		zos.putNextEntry(new ZipEntry("file1"));
		zos.write("testing".getBytes());
		zos.closeEntry();
		zos.close();
		
		String tmp = System.getProperty("java.io.tmpdir");
		
		assertFalse(handler.writeConfiguration(tmp + "/blargh" + System.currentTimeMillis(), os.toByteArray()));
		assertTrue(handler.writeConfiguration(homeDir.getAbsolutePath(), os.toByteArray()));

		String contents = FileUtils.readFileToString(new File(homeDir, "file1"));
		assertEquals("testing", contents);
	}
	
	@Test
	public void testGenerateZipFile() throws Exception {
		EntityDescriptor descriptor = handler.generateSPDescriptor("base", "entity", credential, "orgName", "orgUrl", "email",
				"phone", "givenName", "surName",
				true, true, true, true, false,
				false, false, false);
		File zipFile = handler.generateZipFile("/saml", "password", "idpMetadata".getBytes(), "keystore".getBytes(), descriptor, false);
		assertNotNull(zipFile);
		
		ZipFile f = new ZipFile(zipFile);
		assertNotNull(f.getEntry(SAMLUtil.OIOSAML_DEFAULT_CONFIGURATION_FILE));
		assertNotNull(f.getEntry("metadata/SP/SPMetadata.xml"));
		assertNotNull(f.getEntry("metadata/IdP/IdPMetadata.xml"));
		assertNotNull(f.getEntry("certificate/keystore"));
		assertNotNull(f.getEntry("oiosaml-sp.log4j.xml"));
	}
}
