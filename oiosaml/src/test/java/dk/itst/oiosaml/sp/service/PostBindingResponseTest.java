package dk.itst.oiosaml.sp.service;

import static org.junit.Assert.fail;
import static dk.itst.oiosaml.sp.service.TestHelper.*;

import java.util.HashMap;

import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.model.validation.OIOSAMLAssertionValidator;
import dk.itst.oiosaml.sp.service.SAMLAssertionConsumerHandler;
import dk.itst.oiosaml.sp.service.session.Request;
import dk.itst.oiosaml.sp.service.util.Constants;

public class PostBindingResponseTest extends AbstractServiceTests {
	
	private SAMLAssertionConsumerHandler sh;
	private Response response;
	private RequestContext ctx;

	@Before
	public void setUp() throws Exception {
		
		sh = new SAMLAssertionConsumerHandler(TestHelper.buildConfiguration(new HashMap<String, String>() {{
			put(Constants.PROP_VALIDATOR, OIOSAMLAssertionValidator.class.getName());
		}}));

		response = SAMLUtil.buildXMLObject(Response.class);
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("uri"));
			allowing(req).getQueryString(); will(returnValue("query"));
		}});
		ctx = new RequestContext(req, res, idpMetadata, spMetadata, credential, buildConfiguration(new HashMap<String, String>()), handler, bindingHandlerFactory);
	}

	@Test(expected=RuntimeException.class)
	public void failOnMissingSignature() throws Exception {
		response.setStatus(SAMLUtil.createStatus(StatusCode.SUCCESS_URI));
		final String encoded = encodeResponse(response);
		
		context.checking(new Expectations() {{
			atLeast(1).of(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(encoded));
			allowing(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(""));
		}});
		
		sh.handlePost(ctx);
	}

	
	@Test
	public void failOnNoAssertions() throws Exception {
		response.setStatus(SAMLUtil.createStatus(StatusCode.SUCCESS_URI));
		
		final String xml = TestHelper.signObject(response, credential);
		context.checking(new Expectations() {{
			atLeast(1).of(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(Base64.encodeBytes(xml.getBytes())));
			allowing(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(""));
		}});
		
		try {
			sh.handlePost(ctx);
			fail("No assertions in response");
		} catch (RuntimeException e) {}
	}
	
	@Test
	public void handleSuccess() throws Exception {
		response.setStatus(SAMLUtil.createStatus(StatusCode.SUCCESS_URI));
		response.setDestination(spMetadata.getAssertionConsumerServiceLocation(0));

		Assertion assertion = TestHelper.buildAssertion(spMetadata.getAssertionConsumerServiceLocation(0), spMetadata.getEntityID());
		
		Signature signature = SAMLUtil.buildXMLObject(Signature.class);
	    signature.setSigningCredential(credential);
        SecurityHelper.prepareSignatureParams(signature, credential, null, null);
        assertion.setSignature(signature);
	    SAMLUtil.marshallObject(assertion);
        Signer.signObject(signature);
		
		response.getAssertions().add(assertion);
		
		final String xml = TestHelper.signObject(response, credential);
		context.checking(new Expectations() {{
			atLeast(1).of(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(Base64.encodeBytes(xml.getBytes())));
			allowing(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(handler.saveRequest(new Request("uri", "query", "GET", new HashMap<String, String[]>()))));
			one(session).setAttribute(with(equal(Constants.SESSION_USER_ASSERTION)), with(any(UserAssertion.class)));
			one(res).sendRedirect("uri?query");
			one(req).getCookies(); will(returnValue(null));
			one(session).getMaxInactiveInterval(); will(returnValue(30));
		}});
		
		expectCacheHeaders();
		sh.handlePost(ctx);
	}
	
	@Test
	public void failOnWrongDestination() throws Exception {
		response.setStatus(SAMLUtil.createStatus(StatusCode.SUCCESS_URI));
		response.setDestination("http://consumer");
		Assertion assertion = TestHelper.buildAssertion(spMetadata.getAssertionConsumerServiceLocation(0), spMetadata.getEntityID());
		response.getAssertions().add(assertion);
		
		final String xml = TestHelper.signObject(response, credential);
		context.checking(new Expectations() {{
			atLeast(1).of(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(Base64.encodeBytes(xml.getBytes())));
			allowing(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(""));
		}});
		
		try {
			sh.handlePost(ctx);
			fail("Wrong destination, should  fail");
		} catch (RuntimeException e) {}
	}
	
	
	private String encodeResponse(Response response) {
		final String encoded = Base64.encodeBytes(SAMLUtil.getSAMLObjectAsPrettyPrintXML(response).getBytes());
		return encoded;
	}
}
