package dk.gov.oio.saml.servlet;

import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.StatusCode;

import dk.gov.oio.saml.service.BaseServiceTest;
import dk.gov.oio.saml.service.OIOSAML3Service;
import dk.gov.oio.saml.session.LogoutRequestWrapper;
import dk.gov.oio.saml.session.SessionHandler;
import dk.gov.oio.saml.util.ExternalException;
import dk.gov.oio.saml.util.IdpUtil;
import dk.gov.oio.saml.util.TestConstants;

public class LogoutResponseHandlerTest extends BaseServiceTest {
    private static final String NAME_ID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
    private static final String ERROR_URL = String.format("/%s/%s", TestConstants.SP_ROUTING_BASE, TestConstants.SP_ROUTING_ERROR);

    @DisplayName("Test that a signed successful LogoutResponse to the sent LogoutRequest completes the logout")
    @Test
    public void testValidLogoutResponse() throws Exception {
        LogoutRequest sent = sentLogoutRequest();
        HttpSession session = sessionWith(sent);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        new LogoutResponseHandler().handlePost(postRequest(session, idpResponse(sent.getID(), StatusCode.SUCCESS)), response);

        Mockito.verify(response).sendRedirect("/");
        Mockito.verify(session).invalidate();
    }

    @DisplayName("Test that a signed unsuccessful LogoutResponse leads to the error page")
    @Test
    public void testUnsuccessfulLogoutResponse() throws Exception {
        LogoutRequest sent = sentLogoutRequest();
        HttpSession session = sessionWith(sent);
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        new LogoutResponseHandler().handlePost(postRequest(session, idpResponse(sent.getID(), StatusCode.RESPONDER)), response);

        Mockito.verify(response).sendRedirect(ERROR_URL);
    }

    @DisplayName("Test that an unsigned LogoutResponse is rejected")
    @Test
    public void testRejectUnsignedLogoutResponse() throws Exception {
        LogoutRequest sent = sentLogoutRequest();
        assertRejected(sessionWith(sent), IdpUtil.createIdpLogoutResponse(sent.getID(), logoutResponseUrl(),
                StatusCode.RESPONDER, "<b>status</b>", TestConstants.IDP_ENTITY_ID, false, true));
    }

    @DisplayName("Test that a LogoutResponse signed with an unknown key is rejected")
    @Test
    public void testRejectLogoutResponseSignedWithUnknownKey() throws Exception {
        LogoutRequest sent = sentLogoutRequest();
        assertRejected(sessionWith(sent), IdpUtil.createIdpLogoutResponse(sent.getID(), logoutResponseUrl(),
                StatusCode.SUCCESS, null, TestConstants.IDP_ENTITY_ID, true, false));
    }

    @DisplayName("Test that a LogoutResponse from another issuer is rejected")
    @Test
    public void testRejectLogoutResponseFromUnknownIssuer() throws Exception {
        LogoutRequest sent = sentLogoutRequest();
        assertRejected(sessionWith(sent), IdpUtil.createIdpLogoutResponse(sent.getID(), logoutResponseUrl(),
                StatusCode.SUCCESS, null, "https://not-the-configured-idp", true, true));
    }

    @DisplayName("Test that a LogoutResponse to another LogoutRequest is rejected")
    @Test
    public void testRejectLogoutResponseToOtherRequest() throws Exception {
        LogoutRequest sent = sentLogoutRequest();
        assertRejected(sessionWith(sent), idpResponse(sentLogoutRequest().getID(), StatusCode.SUCCESS));
    }

    @DisplayName("Test that a LogoutResponse is rejected when no LogoutRequest was sent from the session")
    @Test
    public void testRejectLogoutResponseWithoutPendingRequest() throws Exception {
        assertRejected(sessionWith(null), idpResponse(sentLogoutRequest().getID(), StatusCode.SUCCESS));
    }

    @DisplayName("Test that a LogoutResponse for another endpoint is rejected")
    @Test
    public void testRejectLogoutResponseForOtherDestination() throws Exception {
        LogoutRequest sent = sentLogoutRequest();
        assertRejected(sessionWith(sent), IdpUtil.createIdpLogoutResponse(sent.getID(), "https://other-sp.example/saml/logout/response",
                StatusCode.SUCCESS, null, TestConstants.IDP_ENTITY_ID, true, true));
    }

    private void assertRejected(HttpSession session, LogoutResponse logoutResponse) throws Exception {
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

        Assertions.assertThrows(ExternalException.class, () -> new LogoutResponseHandler().handlePost(postRequest(session, logoutResponse), response));

        Mockito.verify(response, Mockito.never()).sendRedirect(Mockito.anyString());
        Mockito.verify(session, Mockito.never()).setAttribute(Mockito.anyString(), Mockito.any());
    }

    private static String logoutResponseUrl() {
        return OIOSAML3Service.getConfig().getServletLogoutResponseURL();
    }

    private static LogoutRequest sentLogoutRequest() throws Exception {
        return IdpUtil.createLogoutRequest(NAME_ID, NameID.PERSISTENT, TestConstants.IDP_LOGOUT_REQUEST_URL);
    }

    private static LogoutResponse idpResponse(String inResponseTo, String statusCode) throws Exception {
        return IdpUtil.createIdpLogoutResponse(inResponseTo, logoutResponseUrl(), statusCode, null, TestConstants.IDP_ENTITY_ID, true, true);
    }

    /**
     * A session as the SP leaves it after sending the LogoutRequest, or without one if null.
     */
    private static HttpSession sessionWith(LogoutRequest sent) throws Exception {
        HttpSession session = Mockito.mock(HttpSession.class);
        SessionHandler sessionHandler = OIOSAML3Service.getSessionHandlerFactory().getHandler();
        Mockito.when(sessionHandler.getLogoutRequest(session)).thenReturn(sent == null ? null : new LogoutRequestWrapper(sent));
        return session;
    }

    /**
     * The LogoutResponse delivered with the HTTP-POST binding.
     */
    private static HttpServletRequest postRequest(HttpSession session, LogoutResponse logoutResponse) throws Exception {
        String xml = SerializeSupport.nodeToString(XMLObjectSupport.marshall(logoutResponse));

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer(logoutResponseUrl()));
        Mockito.when(request.getMethod()).thenReturn("POST");
        Mockito.when(request.getParameter("RelayState")).thenReturn(null);
        Mockito.when(request.getParameter("SAMLResponse")).thenReturn(Base64Support.encode(xml.getBytes(StandardCharsets.UTF_8), Base64Support.UNCHUNKED));
        return request;
    }
}
