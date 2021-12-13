package dk.gov.oio.saml.servlet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import dk.gov.oio.saml.util.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.StatusCode;
import org.w3c.dom.Element;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.OIOSAML3Service;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

public class LogoutRequestHandlerTest {

    @DisplayName("Test that a logged-in user can perform a logout")
    @Test
    public void testLogoutRequestWhenLoggedIn() throws InternalException, IOException, ExternalException, URISyntaxException {
        // Mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);
        Mockito.when(session.getAttribute(Constants.SESSION_NSIS_LEVEL)).thenReturn(NSISLevel.SUBSTANTIAL);
        Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn("true");
        Mockito.when(session.getAttribute(Constants.SESSION_AUTHN_REQUEST)).thenReturn(null);
        Mockito.when(session.getAttribute(Constants.SESSION_NAME_ID)).thenReturn("https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7");
        Mockito.when(session.getAttribute(Constants.SESSION_NAME_ID_FORMAT)).thenReturn(NameID.PERSISTENT);

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
        // Create LogoutRequest
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithLogoutRequest(nameID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL);

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
        Mockito.when(session.getAttribute(Constants.SESSION_NSIS_LEVEL)).thenReturn(NSISLevel.SUBSTANTIAL);
        Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn("true");
        Mockito.when(session.getAttribute(Constants.SESSION_AUTHN_REQUEST)).thenReturn(null);
        Mockito.when(session.getAttribute(Constants.SESSION_NAME_ID)).thenReturn(nameID);
        Mockito.when(session.getAttribute(Constants.SESSION_NAME_ID_FORMAT)).thenReturn(NameID.PERSISTENT);

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
    
    @DisplayName("Test that a user that is not logged in can safely attempt a logout")
    @Test
    public void testLogoutRequestWhenNotLoggedIn() throws InternalException, IOException, ExternalException {
        // Mock session with state: not logged in at any NSIS level
        HttpSession session = Mockito.mock(HttpSession.class);

        // Nothing set since the user is not logged in
        Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn("false");
        Mockito.when(session.getAttribute(Constants.SESSION_AUTHN_REQUEST)).thenReturn(null);
        Mockito.when(session.getAttribute(Constants.SESSION_NAME_ID)).thenReturn(null);
        Mockito.when(session.getAttribute(Constants.SESSION_NAME_ID_FORMAT)).thenReturn(null);

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

        Mockito.verify(session).invalidate();
        Mockito.verify(response).sendRedirect(StringUtil.getUrl(request, OIOSAML3Service.getConfig().getLogoutPage()));
    }

    @DisplayName("Test that an IdP can safely request a logout of a user thas is not logged in")
    @Test
    public void testIdPLogoutRequestWhenNotLoggedIn() throws Exception {
        // Create LogoutRequest
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithLogoutRequest(nameID, NameID.PERSISTENT, TestConstants.SP_LOGOUT_REQUEST_URL);

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
        Mockito.when(session.getAttribute(Constants.SESSION_NSIS_LEVEL)).thenReturn(null);
        Mockito.when(session.getAttribute(Constants.SESSION_AUTHENTICATED)).thenReturn("false");
        Mockito.when(session.getAttribute(Constants.SESSION_AUTHN_REQUEST)).thenReturn(null);
        Mockito.when(session.getAttribute(Constants.SESSION_NAME_ID)).thenReturn(null);
        Mockito.when(session.getAttribute(Constants.SESSION_NAME_ID_FORMAT)).thenReturn(null);

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

        Mockito.verify(session).invalidate();
        Mockito.verify(outputStreamMock).flush(); //Verify that something is sent to the IdP
    }
}
