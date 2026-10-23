package dk.gov.oio.saml.session;

import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnStatement;

import dk.gov.oio.saml.service.BaseServiceTest;
import dk.gov.oio.saml.util.SamlHelper;

public class AssertionWrapperTest extends BaseServiceTest {

    @AfterEach
    public void resetClock() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @DisplayName("Test that the session expires when SessionNotOnOrAfter passes, not only when the wrapper is created")
    @Test
    public void testSessionExpiresWhileWrapperIsKept() throws Exception {
        DateTime start = new DateTime(2026, 10, 19, 12, 0, 0);
        DateTimeUtils.setCurrentMillisFixed(start.getMillis());

        AssertionWrapper wrapper = new AssertionWrapper(assertionWithSessionNotOnOrAfter(start.plusHours(8)));
        Assertions.assertFalse(wrapper.isSessionExpired());

        DateTimeUtils.setCurrentMillisFixed(start.plusHours(8).getMillis());
        Assertions.assertTrue(wrapper.isSessionExpired());
    }

    @DisplayName("Test that a session without SessionNotOnOrAfter does not expire on that account")
    @Test
    public void testSessionWithoutSessionNotOnOrAfter() throws Exception {
        Assertions.assertFalse(new AssertionWrapper(assertionWithSessionNotOnOrAfter(null)).isSessionExpired());
    }

    private static Assertion assertionWithSessionNotOnOrAfter(DateTime sessionNotOnOrAfter) throws Exception {
        Assertion assertion = SamlHelper.build(Assertion.class);
        assertion.setID("_assertion");
        AuthnStatement authnStatement = SamlHelper.build(AuthnStatement.class);
        authnStatement.setSessionIndex("_session");
        authnStatement.setSessionNotOnOrAfter(sessionNotOnOrAfter);
        assertion.getAuthnStatements().add(authnStatement);
        return assertion;
    }
}
