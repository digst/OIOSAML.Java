package dk.gov.oio.saml.servlet;

import java.io.PrintWriter;
import java.io.StringWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import dk.gov.oio.saml.service.BaseServiceTest;
import dk.gov.oio.saml.util.Constants;

public class ErrorHandlerTest extends BaseServiceTest {

    @DisplayName("Test that the error page renders the error message as text, not markup")
    @Test
    public void testErrorMessageIsEscaped() throws Exception {
        String page = render("LOGOUT_ERROR", "Logout failed - response from IdP: <b onclick=\"x\">'status'</b> & more");

        Assertions.assertFalse(page.contains("<b onclick"));
        Assertions.assertTrue(page.contains("&lt;b onclick=&quot;x&quot;&gt;&#39;status&#39;&lt;/b&gt; &amp; more"));
    }

    @DisplayName("Test that the error page renders without an error on the session")
    @Test
    public void testErrorPageWithoutError() throws Exception {
        String page = render(null, null);

        Assertions.assertTrue(page.contains("An unexpected error occurred."));
    }

    private static String render(String type, String message) throws Exception {
        HttpSession session = Mockito.mock(HttpSession.class);
        Mockito.when(session.getAttribute(Constants.SESSION_ERROR_TYPE)).thenReturn(type);
        Mockito.when(session.getAttribute(Constants.SESSION_ERROR_MESSAGE)).thenReturn(message);

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getSession()).thenReturn(session);

        StringWriter output = new StringWriter();
        HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        Mockito.when(response.getWriter()).thenReturn(new PrintWriter(output));

        new ErrorHandler().handleGet(request, response);
        return output.toString();
    }
}
