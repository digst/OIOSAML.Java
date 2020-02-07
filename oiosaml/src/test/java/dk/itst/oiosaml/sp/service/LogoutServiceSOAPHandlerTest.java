package dk.itst.oiosaml.sp.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletResponse;

import org.jmock.Expectations;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.soap11.Envelope;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOLogoutRequest;
import dk.itst.oiosaml.sp.service.LogoutServiceSOAPHandler;

public class LogoutServiceSOAPHandlerTest extends AbstractServiceTests {

	private LogoutServiceSOAPHandler servlet;
	private ByteArrayOutputStream bos;
	private org.apache.commons.configuration.Configuration configuration;
	private RequestContext ctx;
	
	@Before
	public void setUp() throws Exception {
		servlet = new LogoutServiceSOAPHandler();
		configuration = TestHelper.buildConfiguration(new HashMap<String, String>());
		bos = new ByteArrayOutputStream();
		context.checking(new Expectations() {{
			allowing(res).getOutputStream(); will(returnValue(TestHelper.createOutputStream(bos)));
		}});
		ctx = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, handler, bindingHandlerFactory);
	}
	
	@Test
	public void testWsdl() throws Exception {
		final StringWriter w = new StringWriter();
		context.checking(new Expectations() {{
			one(req).getParameter("wsdl"); will(returnValue(""));
			one(res).setContentType("text/xml");
			one(res).setCharacterEncoding("UTF-8");
			one(res).getWriter(); will(returnValue(new PrintWriter(w)));
		}});
		servlet.handleGet(ctx);
		assertTrue(w.toString().indexOf("wsdl:definitions") > -1);
		context.assertIsSatisfied();
		
		context.checking(new Expectations() {{ 
			one(req).getParameter("wsdl"); will(returnValue(null));
			one(res).sendError(with(equal(HttpServletResponse.SC_PRECONDITION_FAILED)), with(any(String.class)));
		}});
		servlet.handleGet(ctx);
	}
	
	@Test(expected=RuntimeException.class)
	public void failWhenBodyIsNotSoap() throws Exception {
		context.checking(new Expectations() {{
			allowing(req).getParameter("wsdl"); will(returnValue(null));
			one(req).getInputStream(); will(returnValue(new ByteInputStream(new ByteArrayInputStream("testing".getBytes()))));
		}});
		servlet.handlePost(ctx);
	}
	
	@Test
	public void testSoapRequest() throws Exception {
		setHandler();
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, spMetadata.getSingleLogoutServiceSOAPLocation(), idpEntityId, handler);
		
		final String xml = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>" + lr.toXML().substring(38) + "</soapenv:Body></soapenv:Envelope>";
		context.checking(new Expectations() {{
			allowing(req).getParameter("wsdl"); will(returnValue(null));
			one(req).getInputStream(); will(returnValue(new ByteInputStream(new ByteArrayInputStream(xml.getBytes()))));
			one(res).setContentLength(with(any(Integer.class)));
			one(res).setCharacterEncoding("UTF-8");
			one(res).setContentType("text/xml");
			one(res).setStatus(HttpServletResponse.SC_OK);
		}});
		
		servlet.handlePost(ctx);
		LogoutResponse res = getResponse();
		
		assertEquals(StatusCode.SUCCESS_URI, res.getStatus().getStatusCode().getValue());
		assertNull(res.getDestination());
		assertEquals(lr.getID(), res.getInResponseTo());
		assertEquals(spMetadata.getEntityID(), res.getIssuer().getValue());
	}
	
	@Test
	public void testSoapRequestWithSignature() throws Exception {
		setHandler();
		OIOLogoutRequest lr = OIOLogoutRequest.buildLogoutRequest(session, spMetadata.getSingleLogoutServiceSOAPLocation(), idpEntityId, handler);
		lr.sign(credential);
		

		final String xml = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>" + lr.toXML().substring(38) + "</soapenv:Body></soapenv:Envelope>";
		context.checking(new Expectations() {{
			allowing(req).getParameter("wsdl"); will(returnValue(null));
			one(req).getInputStream(); will(returnValue(new ByteInputStream(new ByteArrayInputStream(xml.getBytes()))));
			one(res).setContentLength(with(any(Integer.class)));
			one(res).setCharacterEncoding("UTF-8");
			one(res).setContentType("text/xml");
			one(res).setStatus(HttpServletResponse.SC_OK);
		}});

		servlet.handlePost(ctx);
		
		LogoutResponse res = getResponse();
		assertNotNull(res.getSignature());
		
		assertEquals(StatusCode.SUCCESS_URI, res.getStatus().getStatusCode().getValue());
	}
	
	private LogoutResponse getResponse() throws UnsupportedEncodingException {
		Envelope env = (Envelope) SAMLUtil.unmarshallElementFromString(new String(bos.toByteArray(), "UTF-8"));
		LogoutResponse res = (LogoutResponse) env.getBody().getOrderedChildren().get(0);
		return res;
	}
	
	
	private static class ByteInputStream extends ServletInputStream {
		private final InputStream is;
		public ByteInputStream(InputStream is) {
			this.is = is;
		}
		public int read() throws IOException {
			return is.read();
		}
	}
	
}