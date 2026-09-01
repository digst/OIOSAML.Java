package dk.gov.oio.saml.servlet;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import dk.gov.oio.saml.session.AssertionWrapper;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.util.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.StatusCode;
import org.w3c.dom.Element;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.IdPMetadataService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

public class LogoutRequestHandlerTest {

    private static final String NAME_ID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";

    @DisplayName("Test that a logged-in user can perform a logout")
    @Test
    public void testLogoutRequestWhenLoggedIn() throws InternalException, IOException, ExternalException, URISyntaxException {
        HttpSession session = Mockito.mock(HttpSession.class);
        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAssertion(session)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(null);

        // Mock session with state: not logged in at any NSIS level
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(NSISLevel.SUBSTANTIAL);
        Mockito.when(assertionWrapper.getSubjectNameId()).thenReturn(NAME_ID);
        Mockito.when(assertionWrapper.getSubjectNameIdFormat()).thenReturn(NameID.PERSISTENT);

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL)); // URL
        Mockito.when(request.getSession()).thenReturn(session); // Mocked Session
        Mockito.when(request.getMethod()).thenReturn("GET"); // Method: GET
        Mockito.when(request.getParameter("SAMLRequest")).thenReturn(null); // No SAMLRequest (SP-initiated Logout)

        // Mock HttpServletResponse
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        LogoutRequestHandler logoutRequestHandler = new LogoutRequestHandler();
        logoutRequestHandler.handleGet(request, response);

        Mockito.verify(sessionHandler).logout(session, assertionWrapper);
        Mockito.verify(session).invalidate();
        Mockito.verify(response).sendRedirect(Mockito.anyString());

        // Check that LogoutRequest was sent
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(response).sendRedirect(argument.capture());
        URL url = new URL(argument.getValue());
        HashMap<String, String> map = new HashMap<>();
        String query = url.getQuery();
        String[] split = query.split("&");
        for (String s : split) {
            String[] keyValuePair = s.split("=");
            map.put(keyValuePair[0], keyValuePair[1]);
        }
        String samlRequest = map.get("SAMLRequest");
        Assertions.assertNotNull(samlRequest); // Maybe decode and read logoutRequest
    }

    @DisplayName("Test that an IdP can request a logout of a logged-in user")
    @Test
    public void testIdPLogoutRequestWhenLoggedIn() throws Exception {
        HttpSession session = Mockito.mock(HttpSession.class);
        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();

        // Create LogoutRequest
        String nameID = NAME_ID;
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithLogoutRequest(nameID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL);
        String sessionIndex = ((LogoutRequest) messageContext.getMessage()).getSessionIndexes().get(0).getSessionIndex();

        // Marshall and serialize
        Element marshalledMessage = XMLObjectSupport.marshall(messageContext.getMessage());
        String messageXML = SerializeSupport.nodeToString(marshalledMessage);

        // Deflate
        final ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        final DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, new Deflater(8, true));
        deflaterStream.write(messageXML.getBytes("UTF-8"));
        deflaterStream.finish();

        // Base64Encode
        String base64EncodedMessage = Base64Support.encode(bytesOut.toByteArray(), Base64Support.UNCHUNKED);

        // Mock session with state: not logged in at any NSIS level
        Mockito.when(sessionHandler.getAssertion(sessionIndex)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(null);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(NSISLevel.SUBSTANTIAL);
        Mockito.when(assertionWrapper.getSubjectNameId()).thenReturn(nameID);
        Mockito.when(assertionWrapper.getSubjectNameIdFormat()).thenReturn(NameID.PERSISTENT);

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL)); // URL
        Mockito.when(request.getSession()).thenReturn(session); // Mocked Session
        Mockito.when(request.getMethod()).thenReturn("GET"); // Method: GET
        Mockito.when(request.getParameter("RelayState")).thenReturn(null); // No RelayState
        Mockito.when(request.getParameter("SAMLRequest")).thenReturn(base64EncodedMessage);

        // Mock DummyOutputStream
        ServletOutputStream outputStreamMock = Mockito.mock(ServletOutputStream.class);

        // Mock HttpServletResponse
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        Mockito.when(response.getOutputStream()).thenReturn(outputStreamMock);

        // Capture request and parameters
        ArgumentCaptor<MessageContext<SAMLObject>> contextArgumentCaptor = ArgumentCaptor.forClass(MessageContext.class);

        // Spy test class to capture output
        LogoutRequestHandler logoutRequestHandler = Mockito.spy(new LogoutRequestHandler());

        // Action
        logoutRequestHandler.handleGet(request, response);

        // Verification
        Mockito.verify(sessionHandler).logout(session, assertionWrapper);
        Mockito.verify(session).invalidate();
        Mockito.verify(outputStreamMock).flush(); //Verify that something is sent to the IdP
        Mockito.verify(logoutRequestHandler).sendPost(Mockito.eq(response), contextArgumentCaptor.capture());

        // Verify that response is for IDP and from SP
        LogoutResponse logoutResponse = logoutRequestHandler.getSamlObject(contextArgumentCaptor.getAllValues().get(0), LogoutResponse.class);

        Assertions.assertTrue(logoutResponse.isSigned());

        Assertions.assertEquals(StatusCode.SUCCESS, logoutResponse.getStatus().getStatusCode().getValue());
        Assertions.assertEquals(TestConstants.SP_ENTITY_ID, logoutResponse.getIssuer().getValue());
        Assertions.assertEquals(TestConstants.IDP_LOGOUT_RESPONSE_URL, logoutResponse.getDestination());
    }

    @DisplayName("Test that an IdP can request a SOAP logout of a logged-in user")
    @Test
    public void testIdPSOAPLogoutRequestWhenLoggedIn() throws Exception {
        HttpSession session = Mockito.mock(HttpSession.class);
        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();

        // Create LogoutRequest
        String nameID = NAME_ID;
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithLogoutRequest(nameID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL);
        String sessionIndex = ((LogoutRequest) messageContext.getMessage()).getSessionIndexes().get(0).getSessionIndex();

        // Marshall and serialize
        Element marshalledMessage = XMLObjectSupport.marshall(messageContext.getMessage());
        // Serialized as is: indenting or otherwise reformatting the message would break its signature
        final String soapXml = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>" +
                SerializeSupport.nodeToString(marshalledMessage).replaceFirst("^<\\?xml[^>]*\\?>", "") + "</soapenv:Body></soapenv:Envelope>";

        InputStream inputStream = new ByteArrayInputStream(soapXml.getBytes("UTF-8"));

        // Mock session with state: not logged in at any NSIS level
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);
        Mockito.when(sessionHandler.getAssertion(sessionIndex)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(null);
        Mockito.when(assertionWrapper.getNsisLevel()).thenReturn(NSISLevel.SUBSTANTIAL);
        Mockito.when(assertionWrapper.getSubjectNameId()).thenReturn(nameID);
        Mockito.when(assertionWrapper.getSubjectNameIdFormat()).thenReturn(NameID.PERSISTENT);

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL)); // URL
        Mockito.when(request.getSession()).thenReturn(session); // Mocked Session
        Mockito.when(request.getMethod()).thenReturn("POST"); // Method: GET
        Mockito.when(request.getContentType()).thenReturn("text/xml");
        Mockito.when(request.getHeader("SOAPAction")).thenReturn("SOAPAction");
        Mockito.when(request.getInputStream()).thenReturn(new ServletInputStream() {
            public int read() throws IOException {
                return inputStream.read();
            }

            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                //Do nothing
            }
        });

        // Mock DummyOutputStream
        ServletOutputStream outputStreamMock = Mockito.mock(ServletOutputStream.class);

        // Mock HttpServletResponse
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        Mockito.when(response.getOutputStream()).thenReturn(outputStreamMock);

        // Capture request and parameters
        ArgumentCaptor<MessageContext<SAMLObject>> contextArgumentCaptor = ArgumentCaptor.forClass(MessageContext.class);

        // Spy test class to capture output
        LogoutRequestHandler logoutRequestHandler = Mockito.spy(new LogoutRequestHandler());

        // Action
        logoutRequestHandler.handleSOAP(request, response);

        // Verification
        Mockito.verify(sessionHandler).logout(session, assertionWrapper);
        Mockito.verify(session).invalidate();
        Mockito.verify(outputStreamMock).flush(); //Verify that something is sent to the IdP
        Mockito.verify(logoutRequestHandler).sendSOAP(Mockito.eq(response), contextArgumentCaptor.capture());

        // Verify that response is for IDP and from SP
        LogoutResponse logoutResponse = logoutRequestHandler.getSamlObject(contextArgumentCaptor.getAllValues().get(0), LogoutResponse.class);

        Assertions.assertTrue(logoutResponse.isSigned());

        Assertions.assertEquals(StatusCode.SUCCESS, logoutResponse.getStatus().getStatusCode().getValue());
        Assertions.assertEquals(TestConstants.SP_ENTITY_ID, logoutResponse.getIssuer().getValue());
        Assertions.assertEquals(TestConstants.IDP_LOGOUT_RESPONSE_URL, logoutResponse.getDestination());
    }

    @DisplayName("Test that an IdP can request a logout with a signature on the query string")
    @Test
    public void testIdPLogoutRequestSignedOnQueryString() throws Exception {
        HttpSession session = Mockito.mock(HttpSession.class);
        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();

        // Create LogoutRequest without a signature on the message itself, the HTTP-Redirect binding signs
        // the query string instead
        String nameID = NAME_ID;
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithLogoutRequest(nameID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL, false, true);
        String sessionIndex = ((LogoutRequest) messageContext.getMessage()).getSessionIndexes().get(0).getSessionIndex();
        String redirectUrl = IdpUtil.encodeAsRedirectUrl(messageContext);

        Mockito.when(sessionHandler.getAssertion(sessionIndex)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(null);

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));
        Mockito.when(request.getSession()).thenReturn(session);
        Mockito.when(request.getMethod()).thenReturn("GET");
        IdpUtil.stubRedirectRequest(request, redirectUrl);

        // Mock HttpServletResponse
        ServletOutputStream outputStreamMock = Mockito.mock(ServletOutputStream.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        Mockito.when(response.getOutputStream()).thenReturn(outputStreamMock);

        new LogoutRequestHandler().handleGet(request, response);

        Mockito.verify(sessionHandler).logout(session, assertionWrapper);
        Mockito.verify(session).invalidate();
    }

    @DisplayName("Test that a LogoutRequest without a signature is rejected")
    @Test
    public void testRejectUnsignedLogoutRequest() throws Exception {
        assertLogoutRequestRejected(IdpUtil.createMessageWithLogoutRequest(
                NAME_ID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL, false, true));
    }

    @DisplayName("Test that a LogoutRequest signed with an unknown key is rejected")
    @Test
    public void testRejectLogoutRequestSignedWithUnknownKey() throws Exception {
        assertLogoutRequestRejected(IdpUtil.createMessageWithLogoutRequest(
                NAME_ID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL, true, false));
    }

    @DisplayName("Test that a LogoutRequest from another issuer is rejected")
    @Test
    public void testRejectLogoutRequestFromUnknownIssuer() throws Exception {
        assertLogoutRequestRejected(IdpUtil.createMessageWithLogoutRequest(
                NAME_ID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL, true, true, "https://not-the-configured-idp"));
    }

    @DisplayName("Test that a LogoutRequest signed with any of the signing certificates in metadata is accepted")
    @Test
    public void testLogoutRequestSignedWithSecondCertificateInMetadata() throws Exception {
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithLogoutRequest(
                NAME_ID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL);

        withIdPMetadata(metadataWithTwoSigningCertificates(), () -> assertLogoutRequestAccepted(messageContext, false));
    }

    @DisplayName("Test that a query string signed with any of the signing certificates in metadata is accepted")
    @Test
    public void testLogoutRequestSignedOnQueryStringWithSecondCertificateInMetadata() throws Exception {
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithLogoutRequest(
                NAME_ID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL, false, true);

        withIdPMetadata(metadataWithTwoSigningCertificates(), () -> assertLogoutRequestAccepted(messageContext, true));
    }

    @DisplayName("Test that a LogoutRequest is rejected when metadata holds no signing certificate")
    @Test
    public void testRejectLogoutRequestWhenMetadataHasNoSigningCertificate() throws Exception {
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithLogoutRequest(
                NAME_ID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL);

        // Without a certificate there is nothing to validate the signature against, so the request cannot be
        // accepted on the grounds that no validation failed
        withIdPMetadata(metadataWithoutSigningCertificate(),
                () -> assertLogoutRequestRejected(messageContext, InternalException.class));
    }

    /**
     * Send the LogoutRequest to the handler and require that the session it names is logged out.
     */
    private void assertLogoutRequestAccepted(MessageContext<SAMLObject> messageContext, boolean signedOnQueryString) throws Exception {
        HttpSession session = Mockito.mock(HttpSession.class);
        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();

        String sessionIndex = ((LogoutRequest) messageContext.getMessage()).getSessionIndexes().get(0).getSessionIndex();
        Mockito.when(sessionHandler.getAssertion(sessionIndex)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(null);

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));
        Mockito.when(request.getSession()).thenReturn(session);
        Mockito.when(request.getMethod()).thenReturn("GET");

        if (signedOnQueryString) {
            IdpUtil.stubRedirectRequest(request, IdpUtil.encodeAsRedirectUrl(messageContext));
        } else {
            Mockito.when(request.getParameter("RelayState")).thenReturn(null);
            Mockito.when(request.getParameter("SAMLRequest")).thenReturn(deflateAndEncode(messageContext));
        }

        // Mock HttpServletResponse
        ServletOutputStream outputStreamMock = Mockito.mock(ServletOutputStream.class);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        Mockito.when(response.getOutputStream()).thenReturn(outputStreamMock);

        new LogoutRequestHandler().handleGet(request, response);

        Mockito.verify(sessionHandler).logout(session, assertionWrapper);
        Mockito.verify(session).invalidate();
    }

    /**
     * Run the action with the library pointed at the given IdP metadata, as a deployment is while the IdP
     * rotates its signing key.
     */
    private void withIdPMetadata(String metadata, TestAction action) throws Exception {
        String originalMetadataFile = OIOSAML3Service.getConfig().getIdpMetadataFile();
        OIOSAML3Service.getConfig().setIdpMetadataFile(TestConstants.writeIdpMetadataFile(metadata));
        IdPMetadataService.getInstance().clear(TestConstants.IDP_ENTITY_ID);

        try {
            action.run();
        } finally {
            OIOSAML3Service.getConfig().setIdpMetadataFile(originalMetadataFile);
            IdPMetadataService.getInstance().clear(TestConstants.IDP_ENTITY_ID);
        }
    }

    @FunctionalInterface
    private interface TestAction {
        void run() throws Exception;
    }

    /**
     * Marshall, deflate and base64 encode the message as the HTTP-Redirect binding does.
     */
    private static String deflateAndEncode(MessageContext<SAMLObject> messageContext) throws Exception {
        Element marshalledMessage = XMLObjectSupport.marshall(messageContext.getMessage());

        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, new Deflater(8, true));
        deflaterStream.write(SerializeSupport.nodeToString(marshalledMessage).getBytes("UTF-8"));
        deflaterStream.finish();

        return Base64Support.encode(bytesOut.toByteArray(), Base64Support.UNCHUNKED);
    }

    /**
     * Metadata where the certificate actually used for signing is preceded by another one, as it is while the
     * IdP rotates its signing key.
     */
    private static String metadataWithTwoSigningCertificates() throws Exception {
        String otherCertificate = IdpUtil.getIdpCertificateBase64(false);

        return TestConstants.IDP_METADATA.replaceFirst("<md:KeyDescriptor use=\"signing\">",
                "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>"
                        + otherCertificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"signing\">");
    }

    /**
     * Metadata publishing no key for signing, as it is when every published certificate has been revoked.
     */
    private static String metadataWithoutSigningCertificate() {
        return TestConstants.IDP_METADATA.replace("<md:KeyDescriptor use=\"signing\">", "<md:KeyDescriptor use=\"encryption\">");
    }

    /**
     * Send the LogoutRequest to the handler and require that it is refused without any session being touched.
     */
    private void assertLogoutRequestRejected(MessageContext<SAMLObject> messageContext) throws Exception {
        assertLogoutRequestRejected(messageContext, ExternalException.class);
    }

    private void assertLogoutRequestRejected(MessageContext<SAMLObject> messageContext, Class<? extends Exception> expected) throws Exception {
        HttpSession session = Mockito.mock(HttpSession.class);
        AssertionWrapper assertionWrapper = Mockito.mock(AssertionWrapper.class);
        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();

        String sessionIndex = ((LogoutRequest) messageContext.getMessage()).getSessionIndexes().get(0).getSessionIndex();
        Mockito.when(sessionHandler.getAssertion(sessionIndex)).thenReturn(assertionWrapper);
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(true);
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(null);

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL));
        Mockito.when(request.getSession()).thenReturn(session);
        Mockito.when(request.getMethod()).thenReturn("GET");
        Mockito.when(request.getParameter("RelayState")).thenReturn(null);
        Mockito.when(request.getParameter("SAMLRequest")).thenReturn(deflateAndEncode(messageContext));

        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        Assertions.assertThrows(expected, () -> new LogoutRequestHandler().handleGet(request, response));

        // The session handler mock is shared between tests, so verify against this tests own session
        Mockito.verify(sessionHandler, Mockito.never()).logout(Mockito.eq(session), Mockito.any(AssertionWrapper.class));
        Mockito.verify(session, Mockito.never()).invalidate();
    }

    @DisplayName("Test that a user that is not logged in can safely attempt a logout")
    @Test
    public void testLogoutRequestWhenNotLoggedIn() throws InternalException, IOException, ExternalException {
        // Mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(null);

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL)); // URL
        Mockito.when(request.getSession()).thenReturn(session); // Mocked Session
        Mockito.when(request.getMethod()).thenReturn("GET"); // Method: GET
        Mockito.when(request.getParameter("SAMLRequest")).thenReturn(null); // No SAMLRequest (SP-initiated Logout)

        // Mock HttpServletResponse
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        LogoutRequestHandler logoutRequestHandler = new LogoutRequestHandler();
        logoutRequestHandler.handleGet(request, response);

        Mockito.verify(sessionHandler, Mockito.never()).getAssertion(Mockito.eq(session));
        Mockito.verify(sessionHandler, Mockito.never()).logout(Mockito.eq(session), Mockito.any(AssertionWrapper.class));
        Mockito.verify(session).invalidate();
        Mockito.verify(response).sendRedirect(StringUtil.getUrl(request, OIOSAML3Service.getConfig().getLogoutPage()));
    }

    @DisplayName("Test that a user that is not logged in can safely attempt a SOAP logout")
    @Test
    public void testSOAPLogoutRequestWhenNotLoggedIn() throws Exception {
        // Create LogoutRequest
        String nameID = NAME_ID;
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithLogoutRequest(nameID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL);
        String sessionIndex = ((LogoutRequest) messageContext.getMessage()).getSessionIndexes().get(0).getSessionIndex();

        // Marshall and serialize
        Element marshalledMessage = XMLObjectSupport.marshall(messageContext.getMessage());
        // Serialized as is: indenting or otherwise reformatting the message would break its signature
        final String soapXml = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>" +
                SerializeSupport.nodeToString(marshalledMessage).replaceFirst("^<\\?xml[^>]*\\?>", "") + "</soapenv:Body></soapenv:Envelope>";

        InputStream inputStream = new ByteArrayInputStream(soapXml.getBytes("UTF-8"));

        // Mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(null);

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL)); // URL
        Mockito.when(request.getSession()).thenReturn(session); // Mocked Session
        Mockito.when(request.getMethod()).thenReturn("POST"); // Method: GET
        Mockito.when(request.getContentType()).thenReturn("text/xml");
        Mockito.when(request.getHeader("SOAPAction")).thenReturn("SOAPAction");
        Mockito.when(request.getInputStream()).thenReturn(new ServletInputStream() {
            public int read() throws IOException {
                return inputStream.read();
            }

            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                //Do nothing
            }
        });

        // Mock DummyOutputStream
        ServletOutputStream outputStreamMock = Mockito.mock(ServletOutputStream.class);

        // Mock HttpServletResponse
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        Mockito.when(response.getOutputStream()).thenReturn(outputStreamMock);

        // Capture request and parameters
        ArgumentCaptor<MessageContext<SAMLObject>> contextArgumentCaptor = ArgumentCaptor.forClass(MessageContext.class);

        // Spy test class to capture output
        LogoutRequestHandler logoutRequestHandler = Mockito.spy(new LogoutRequestHandler());

        // Action
        logoutRequestHandler.handleSOAP(request, response);

        // Verification
        Mockito.verify(sessionHandler, Mockito.never()).getAssertion(session);
        Mockito.verify(sessionHandler, Mockito.times(1)).getAssertion(sessionIndex);
        Mockito.verify(sessionHandler, Mockito.never()).logout(Mockito.eq(session), Mockito.any(AssertionWrapper.class));
        Mockito.verify(session).invalidate();
        Mockito.verify(outputStreamMock).flush(); //Verify that something is sent to the IdP
        Mockito.verify(logoutRequestHandler).sendSOAP(Mockito.eq(response), contextArgumentCaptor.capture());

        // Verify that response is for IDP and from SP
        LogoutResponse logoutResponse = logoutRequestHandler.getSamlObject(contextArgumentCaptor.getAllValues().get(0), LogoutResponse.class);

        Assertions.assertTrue(logoutResponse.isSigned());

        Assertions.assertEquals(StatusCode.SUCCESS, logoutResponse.getStatus().getStatusCode().getValue());
        Assertions.assertEquals(TestConstants.SP_ENTITY_ID, logoutResponse.getIssuer().getValue());
        Assertions.assertEquals(TestConstants.IDP_LOGOUT_RESPONSE_URL, logoutResponse.getDestination());
    }

    @DisplayName("Test that an IdP can safely request a logout of a user thas is not logged in")
    @Test
    public void testIdPLogoutRequestWhenNotLoggedIn() throws Exception {
        // Create LogoutRequest
        String nameID = NAME_ID;
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithLogoutRequest(nameID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL);
        String sessionIndex = ((LogoutRequest) messageContext.getMessage()).getSessionIndexes().get(0).getSessionIndex();

        // Marshall and serialize
        Element marshalledMessage = XMLObjectSupport.marshall(messageContext.getMessage());
        String messageXML = SerializeSupport.nodeToString(marshalledMessage);

        // Deflate
        final ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        final DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, new Deflater(8, true));
        deflaterStream.write(messageXML.getBytes("UTF-8"));
        deflaterStream.finish();

        // Base64Encode
        String base64EncodedMessage = Base64Support.encode(bytesOut.toByteArray(), Base64Support.UNCHUNKED);

        // Mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.isAuthenticated(session)).thenReturn(false);
        Mockito.when(sessionHandler.getAssertion(sessionIndex)).thenReturn(null);
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(null);

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL)); // URL
        Mockito.when(request.getSession()).thenReturn(session); // Mocked Session
        Mockito.when(request.getMethod()).thenReturn("GET"); // Method: GET
        Mockito.when(request.getParameter("RelayState")).thenReturn(null); // No RelayState
        Mockito.when(request.getParameter("SAMLRequest")).thenReturn(base64EncodedMessage);

        // Mock DummyOutputStream
        ServletOutputStream outputStreamMock = Mockito.mock(ServletOutputStream.class);

        // Mock HttpServletResponse
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        Mockito.when(response.getOutputStream()).thenReturn(outputStreamMock);

        LogoutRequestHandler logoutRequestHandler = new LogoutRequestHandler();
        logoutRequestHandler.handleGet(request, response);

        Mockito.verify(sessionHandler, Mockito.never()).getAssertion(session);
        Mockito.verify(sessionHandler, Mockito.times(1)).getAssertion(sessionIndex);
        Mockito.verify(sessionHandler, Mockito.never()).logout(Mockito.eq(session), Mockito.any(AssertionWrapper.class));
        Mockito.verify(session).invalidate();
        Mockito.verify(outputStreamMock).flush(); //Verify that something is sent to the IdP
    }
}
