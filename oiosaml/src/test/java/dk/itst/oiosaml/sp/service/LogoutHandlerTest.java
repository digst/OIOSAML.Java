package dk.itst.oiosaml.sp.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;

import org.apache.commons.configuration.Configuration;
import org.jmock.Expectations;
import org.junit.Test;
import org.opensaml.saml2.core.LogoutRequest;
import org.w3c.dom.Document;

import dk.itst.oiosaml.sp.service.LogoutHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;

public class LogoutHandlerTest extends AbstractServiceTests {

	private Configuration configuration;

	@Test
	public void testLogout() throws Exception {
		LogoutHandler servlet = new LogoutHandler();

		configuration = TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_HOME, "url");
		}});

		context.checking(new Expectations() {{
			// GET with no session must redirect to home url
			one(res).sendRedirect("url");
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
			allowing(req).getContextPath(); will(returnValue("/"));
		}});
		RequestContext ctx = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, handler, bindingHandlerFactory);
		servlet.handleGet(ctx);

		setHandler();
		final StringValueHolder val = new StringValueHolder();
		context.checking(new Expectations() {{
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
			one(res).sendRedirect(with(val));
		}});
		servlet.handleGet(ctx);
		
		assertTrue(val.getValue().contains("?SAMLRequest"));
		
		String req = Utils.getParameter("SAMLRequest", val.getValue());
		Document doc = TestHelper.parseBase64Encoded(req, true);
		LogoutRequest lr = (LogoutRequest) org.opensaml.xml.Configuration.getUnmarshallerFactory().getUnmarshaller(doc.getDocumentElement()).unmarshall(doc.getDocumentElement());
		
		assertEquals(idpMetadata.getFirstMetadata().getEntityID(), handler.removeEntityIdForRequest(lr.getID()));
	}
}
