package dk.itst.oiosaml.sp.bindings;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.jmock.Expectations;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.w3c.dom.Document;

import dk.itst.oiosaml.sp.model.OIOAuthnRequest;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.Utils;


public class RedirectBindingHandlerTest extends AbstractServiceTests {

	
	@Test
	public void testHandle() throws Exception {
		RedirectBindingHandler rh = new RedirectBindingHandler();
		
		final StringWriter sw = new StringWriter();
		context.checking(new Expectations() {{
			allowing(req).getCookies(); will(returnValue(null));
			allowing(res).addHeader(with(any(String.class)), with(any(String.class)));
			allowing(res).addDateHeader(with(any(String.class)), with(any(Long.class)));
			one(res).setContentType("text/html");
			one(res).getWriter(); will(returnValue(new PrintWriter(sw)));
		}});
		OIOAuthnRequest request = OIOAuthnRequest.buildAuthnRequest("http://ssoServiceLocation", "spEntityId", SAMLConstants.SAML2_ARTIFACT_BINDING_URI, handler, "state", "http://localhost");

		rh.handle(req, res, credential, request);
		
		String url = sw.toString().substring(sw.toString().indexOf("url=") + 4, sw.toString().indexOf(">", sw.toString().indexOf("url=")) - 1);
		String r = Utils.getParameter("SAMLRequest", url);
		TestHelper.validateUrlSignature(credential, url, r, "SAMLRequest");
		
		Document document = TestHelper.parseBase64Encoded(r);
		AuthnRequest ar = (AuthnRequest) Configuration.getUnmarshallerFactory().getUnmarshaller(document.getDocumentElement()).unmarshall(document.getDocumentElement());
		assertEquals("http://ssoServiceLocation", ar.getDestination());
		assertEquals("spEntityId", ar.getIssuer().getValue());
		assertNotNull(ar.getID());
	}
}
