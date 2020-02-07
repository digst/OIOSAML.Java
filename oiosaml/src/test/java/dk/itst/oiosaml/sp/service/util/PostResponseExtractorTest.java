package dk.itst.oiosaml.sp.service.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOResponse;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.util.PostResponseExtractor;

public class PostResponseExtractorTest extends AbstractServiceTests {
	
	private PostResponseExtractor extractor;

	@Before
	public void setUp() {
		extractor = new PostResponseExtractor();
	}

	@Test
	public void testExtract() throws Exception {
		Response response = SAMLUtil.buildXMLObject(Response.class);
		response.setConsent("consent");
		final String xml = SAMLUtil.getSAMLObjectAsPrettyPrintXML(response);
		final String encodedMessage = Base64.encodeBytes(xml.getBytes(), Base64.DONT_BREAK_LINES);

		context.checking(new Expectations() {{
			atLeast(1).of(req).getParameter("SAMLResponse"); will(returnValue(encodedMessage));
		}});
		OIOResponse newResponse = extractor.extract(req);
		assertEquals("consent", newResponse.getResponse().getConsent());
	}
	
	@Test(expected=IllegalStateException.class)
	public void failOnMissingParameter() {
		context.checking(new Expectations() {{
			atLeast(1).of(req).getParameter("SAMLResponse"); will(returnValue(null));
		}});
		extractor.extract(req);
	}
	
	@Test
	public void failOnWrongType() throws Exception {
		Marshaller m = (Marshaller) Configuration.getMarshallerFactory().getMarshaller(assertion);
		m.marshall(assertion);
		String messageXML = XMLHelper.nodeToString(assertion.getDOM());
		final String encodedMessage = Base64.encodeBytes(messageXML.getBytes(), Base64.DONT_BREAK_LINES);
		
		context.checking(new Expectations() {{
			atLeast(1).of(req).getParameter("SAMLResponse"); will(returnValue(encodedMessage));
		}});
		
		try {
			extractor.extract(req);
			fail("Wrong response type, should fail");
		} catch (RuntimeException e) {}
	}


}
