package dk.itst.oiosaml.sp.bindings;

import static dk.itst.oiosaml.sp.service.TestHelper.parseBase64Encoded;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import javax.servlet.RequestDispatcher;

import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.w3c.dom.Document;

import dk.itst.oiosaml.sp.model.OIOAuthnRequest;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.StringValueHolder;

public class PostBindingHandlerTest extends AbstractServiceTests{

	private String dispatchPath;
	private PostBindingHandler ph;
	private StringValueHolder samlRequestBase64Encoded;
	String serviceLocation;
	private String entityId;
	private OIOAuthnRequest request;

	@Before
	public void setUp() throws Exception {
		dispatchPath = "testDispatchPath";
		ph = new PostBindingHandler(dispatchPath);
		samlRequestBase64Encoded = new StringValueHolder();
		serviceLocation = "http://sso.url";
		entityId = "SPEntityId";
		request = OIOAuthnRequest.buildAuthnRequest(serviceLocation, entityId, SAMLConstants.SAML2_POST_BINDING_URI, handler, "state", "http://localhost", null);
	}

	@Test
	public void testGetBindingURI() {
		assertEquals(SAMLConstants.SAML2_POST_BINDING_URI, new PostBindingHandler("").getBindingURI());
	}

	@Test
	public void testHandle() throws Exception {
		final RequestDispatcher dispatcher = context.mock(RequestDispatcher.class);
		context.checking(new Expectations() {{
			one(req).getRequestDispatcher(dispatchPath); will(returnValue(dispatcher));
			one(dispatcher).forward(req, res);
			one(req).setAttribute(with(equal("SAMLRequest")), with(samlRequestBase64Encoded));
			one(req).setAttribute(with(equal("RelayState")), with(any(String.class)));
			one(req).setAttribute("action", serviceLocation);
		}});
		ph.handle(req, res, credential, request);
		Document samlRequest = parseBase64Encoded(samlRequestBase64Encoded.getValue(), false);
		AuthnRequest authnRequest = (AuthnRequest)Configuration.getUnmarshallerFactory().getUnmarshaller(samlRequest.getDocumentElement()).unmarshall(samlRequest.getDocumentElement());
		assertEquals(entityId, authnRequest.getIssuer().getValue());
		assertNotNull(authnRequest.getSignature());
		assertTrue(authnRequest.getIssueInstant().isBeforeNow());
		assertEquals(ph.getBindingURI(), authnRequest.getProtocolBinding());
		assertEquals(serviceLocation, authnRequest.getDestination());
	}
	
	@Test(expected=RuntimeException.class)
	public void failOnNoDispatcher() throws Exception {
		context.checking(new Expectations() {{ 
			one(req).getRequestDispatcher(dispatchPath); will(returnValue(null));
			one(req).setAttribute(with(equal("SAMLRequest")), with(samlRequestBase64Encoded));
			one(req).setAttribute(with(equal("RelayState")), with(any(String.class)));
			one(req).setAttribute("action", serviceLocation);
		}});
		ph.handle(req, res, credential, request);		
	}
}
