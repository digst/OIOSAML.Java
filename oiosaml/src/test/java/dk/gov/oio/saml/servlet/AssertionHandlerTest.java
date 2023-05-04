package dk.gov.oio.saml.servlet;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.AuthnRequestService;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.session.AssertionWrapper;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.util.IdpUtil;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.TestConstants;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.w3c.dom.Element;

public class AssertionHandlerTest {

    private HttpSession session;

    @BeforeEach
    public void beforeEach() throws InternalException {
        session = Mockito.mock(HttpSession.class);
        Mockito.when(session.getId()).thenReturn("TEST_SESSION_ID");
    }

    @DisplayName("Test that handler will accept a valid assertion")
    @Test
    public void testPostWithValidAssertion() throws Exception {
        // Create MessageContext, Response and Assertion
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        String inResponseToId = UUID.randomUUID().toString();
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);

        // Marshall serialize and base64 Encode message (Same way HTTPPostEncoder handles outgoing saml requests)
        Element marshalledMessage = XMLObjectSupport.marshall(messageContext.getMessage());
        String messageXML = SerializeSupport.nodeToString(marshalledMessage);
        String base64EncodedMessage = Base64Support.encode(messageXML.getBytes("UTF-8"), Base64Support.UNCHUNKED);

        // Create AuthnRequest
        AuthnRequestService authnRequestService = new AuthnRequestService();
        MessageContext<SAMLObject> authnRequestMessageContext = authnRequestService.createMessageWithAuthnRequest(false, false, NSISLevel.SUBSTANTIAL, null, null);
        AuthnRequest authnRequest = (AuthnRequest) authnRequestMessageContext.getMessage();
        authnRequest.setID(inResponseToId);
        AuthnRequestWrapper wrapper = new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, "");

        // mock session with state: not logged in at any NSIS level
        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(wrapper);


        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL)); // URL
        Mockito.when(request.getSession()).thenReturn(session); // Mocked Session
        Mockito.when(request.getMethod()).thenReturn("POST"); // Method: POST
        Mockito.when(request.getParameter("RelayState")).thenReturn(null); // No RelayState
        Mockito.when(request.getParameter("SAMLResponse")).thenReturn(base64EncodedMessage); // Return base64 encoded SamlResponse

        // Mock HttpServletResponse
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        // Capture the assertion
        ArgumentCaptor<AssertionWrapper> assertionWrapperArgumentCaptor = ArgumentCaptor.forClass(AssertionWrapper.class);

        AssertionHandler assertionHandler = new AssertionHandler();
        assertionHandler.handlePost(request, response);

        Mockito.verify(response).sendRedirect("/"); // Verify that handler redirected
        Mockito.verify(sessionHandler).storeAssertion(Mockito.eq(session), assertionWrapperArgumentCaptor.capture());

        Assertions.assertEquals(assertionWrapperArgumentCaptor.getValue().getNsisLevel(), NSISLevel.SUBSTANTIAL);
    }
    
    @DisplayName("Test that handler will reject am invalid assertion")
    @Test
    public void testPostWithInvalidAssertion() throws Exception {
        // Create MessageContext, Response and Assertion
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        String inResponseToId = UUID.randomUUID().toString();
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, false, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);

        // Marshall serialize and base64 Encode message (Same way HTTPPostEncoder handles outgoing saml requests)
        Element marshalledMessage = XMLObjectSupport.marshall(messageContext.getMessage());
        String messageXML = SerializeSupport.nodeToString(marshalledMessage);
        String base64EncodedMessage = Base64Support.encode(messageXML.getBytes("UTF-8"), Base64Support.UNCHUNKED);

        // Create AuthnRequest
        AuthnRequestService authnRequestService = new AuthnRequestService();
        MessageContext<SAMLObject> authnRequestMessageContext = authnRequestService.createMessageWithAuthnRequest(false, false, NSISLevel.SUBSTANTIAL, null, null);
        AuthnRequest authnRequest = (AuthnRequest) authnRequestMessageContext.getMessage();
        authnRequest.setID(inResponseToId);
        AuthnRequestWrapper wrapper = new AuthnRequestWrapper(authnRequest, NSISLevel.SUBSTANTIAL, "");

        // mock session with state: not logged in at any NSIS level
        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getAuthnRequest(session)).thenReturn(wrapper);

        // Mock HttpServletRequest
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.SP_ASSERTION_CONSUMER_URL)); // URL
        Mockito.when(request.getSession()).thenReturn(session); // Mocked Session
        Mockito.when(request.getMethod()).thenReturn("POST"); // Method: POST
        Mockito.when(request.getParameter("RelayState")).thenReturn(null); // No RelayState
        Mockito.when(request.getParameter("SAMLResponse")).thenReturn(base64EncodedMessage); // Return base64 encoded SamlResponse

        // Mock HttpServletResponse
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        AssertionHandler assertionHandler = new AssertionHandler();

        // Handle Post, should fail due to invalid cert used for encryption, will throw an error and let DispatcherServlet Handle showing the error and redirecting the user
        Assertions.assertThrows(Exception.class , () -> {
            assertionHandler.handlePost(request, response);
        });

        Mockito.verify(sessionHandler, Mockito.never()).storeAssertion(Mockito.eq(session), Mockito.any(AssertionWrapper.class));
        Assertions.assertFalse(sessionHandler.isAuthenticated(session));
    }    
}
