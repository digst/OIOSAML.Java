package dk.gov.oio.saml.session.database;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.AssertionService;
import dk.gov.oio.saml.service.AuthnRequestService;
import dk.gov.oio.saml.session.AssertionWrapper;
import dk.gov.oio.saml.session.AuthnRequestWrapper;
import dk.gov.oio.saml.session.LogoutRequestWrapper;
import dk.gov.oio.saml.util.IdpUtil;
import dk.gov.oio.saml.util.InternalException;
import dk.gov.oio.saml.util.TestConstants;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.opensaml.core.config.InitializationException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpSession;
import javax.sql.DataSource;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.*;
import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseSessionHandlerTest {
    private static final Logger log = LoggerFactory.getLogger(DatabaseSessionHandlerTest.class);
    private static final NSISLevel NSIS_LEVEL = NSISLevel.SUBSTANTIAL;
    private static final String SESSION_ID = "SESSION_ID";
    private static final String REQUEST_URL = "REQUEST_URL";

    // Setup database and tables in HQSQLDB once for all tests (database_session_handler.sql)
    private static DataSource dataSource;

    private DatabaseSessionHandler sessionHandler;
    private HttpSession session;

    @BeforeAll
    static void beforeAll() throws ClassNotFoundException, InternalException {
        Class.forName("org.hsqldb.jdbc.JDBCDriver");
        dataSource = new DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                return  DriverManager.getConnection("jdbc:hsqldb:mem", "SA", "");
            }

            @Override
            public Connection getConnection(String username, String password) throws SQLException {
                return  DriverManager.getConnection("jdbc:hsqldb:mem", "SA", "");
            }

            @Override
            public PrintWriter getLogWriter() throws SQLException {
                return null;
            }

            @Override
            public void setLogWriter(PrintWriter out) throws SQLException {

            }

            @Override
            public void setLoginTimeout(int seconds) throws SQLException {

            }

            @Override
            public int getLoginTimeout() throws SQLException {
                return 0;
            }

            @Override
            public <T> T unwrap(Class<T> iface) throws SQLException {
                return null;
            }

            @Override
            public boolean isWrapperFor(Class<?> iface) throws SQLException {
                return false;
            }

            @Override
            public java.util.logging.Logger getParentLogger() throws SQLFeatureNotSupportedException {
                return null;
            }
        };
        try (Connection connection=dataSource.getConnection()){
            connection.setAutoCommit(true);

            StringBuilder contentBuilder = new StringBuilder();

            try (Stream<String> stream = Files.lines( Paths.get("../misc/database_session_handler.sql"), StandardCharsets.UTF_8)) {
                stream.forEach(s -> contentBuilder.append(s));
            } catch (IOException e) {
                log.error(e.getMessage(), e);
                Assertions.fail(e.getMessage());
            }

            Arrays.stream(contentBuilder.toString().split(";"))
                    .forEach(sql -> {
                        try {
                            connection.createStatement().executeUpdate(sql);
                        } catch (SQLException e) {
                            // HQSQL unable to run statement from DDL script
                            log.debug("Continue without '{}'", sql, e);
                        }
                    });

        } catch (SQLException e) {
            log.error("Failure to setup tables", e);
            throw new InternalException("Failure to setup tables for databaseSessionHandler", e);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        sessionHandler = new DatabaseSessionHandler(dataSource);
        session = Mockito.mock(HttpSession.class);
        Mockito.when(session.getId()).thenReturn(SESSION_ID);
    }

    @DisplayName("Test stored missing AuthnRequest will exit")
    @Test
    void testStoreAuthnRequestMissingAuthnRequest() throws Exception {

        sessionHandler.storeAuthnRequest(session, null);

        // Will never reach biz logic
        Mockito.verify(session, Mockito.never()).getId();
    }

    @DisplayName("Test that stored AuthnRequest can be retrieved")
    @Test
    void testStoreAuthnRequest() throws InternalException, InitializationException {
        AuthnRequestWrapper authnRequestWrapperOld = new AuthnRequestWrapper(createAuthnRequest(), NSIS_LEVEL, REQUEST_URL);
        AuthnRequestWrapper authnRequestWrapperInput = new AuthnRequestWrapper(createAuthnRequest(), NSIS_LEVEL, REQUEST_URL);

        // No output returned before
        AuthnRequestWrapper authnRequestWrapperPreOutput = sessionHandler.getAuthnRequest(session);
        Assertions.assertNull(authnRequestWrapperPreOutput);

        // input is persisted
        sessionHandler.storeAuthnRequest(session, authnRequestWrapperOld);

        AuthnRequestWrapper authnRequestWrapperOldOutput = sessionHandler.getAuthnRequest(session);
        Assertions.assertEquals(authnRequestWrapperOld.getAuthnRequestAsBase64(), authnRequestWrapperOldOutput.getAuthnRequestAsBase64());

        // input is replaced
        sessionHandler.storeAuthnRequest(session, authnRequestWrapperInput);

        AuthnRequestWrapper authnRequestWrapperOutput = sessionHandler.getAuthnRequest(session);
        Assertions.assertEquals(authnRequestWrapperInput.getAuthnRequestAsBase64(), authnRequestWrapperOutput.getAuthnRequestAsBase64());
    }

    @DisplayName("Test that stored AuthnRequest is removed after timeout")
    @Test
    void testStoreAuthnRequestTimeout() throws InternalException, InitializationException {
        AuthnRequestWrapper authnRequestWrapperInput = new AuthnRequestWrapper(createAuthnRequest(), NSIS_LEVEL, REQUEST_URL);

        sessionHandler.storeAuthnRequest(session, authnRequestWrapperInput);
        sessionHandler.cleanup(-1);

        AuthnRequestWrapper authnRequestWrapperOutput = sessionHandler.getAuthnRequest(session);
        Assertions.assertNull(authnRequestWrapperOutput);
    }

    @DisplayName("Test stored missing Assertion will exit")
    @Test
    void testStoreAssertionMissingAssertion() throws Exception {

        sessionHandler.storeAssertion(session, null);

        // Will never reach biz logic
        Mockito.verify(session, Mockito.never()).getId();
    }

    @DisplayName("Test that stored Assertion can be retrieved")
    @Test
    void testStoreAssertion() throws Exception {
        AssertionWrapper assertionWrapperOldInput = new AssertionWrapper(createAssertion());
        AssertionWrapper assertionWrapperInput = new AssertionWrapper(createAssertion());

        // No output returned before
        AssertionWrapper assertionWrapperPreOutput = sessionHandler.getAssertion(session);
        Assertions.assertNull(assertionWrapperPreOutput);

        // input is persisted
        sessionHandler.storeAssertion(session, assertionWrapperOldInput);

        AssertionWrapper assertionWrapperOldOutput = sessionHandler.getAssertion(session);
        Assertions.assertEquals(assertionWrapperOldInput.getAssertionAsBase64(), assertionWrapperOldOutput.getAssertionAsBase64());

        // input is replaced
        sessionHandler.storeAssertion(session, assertionWrapperInput);

        AssertionWrapper assertionWrapperOutput = sessionHandler.getAssertion(session);
        Assertions.assertEquals(assertionWrapperInput.getAssertionAsBase64(), assertionWrapperOutput.getAssertionAsBase64());
    }

    @DisplayName("Test that stored Assertion can be retrieved using session index")
    @Test
    void testStoreAssertionGetSessionIndex() throws Exception {
        AssertionWrapper assertionWrapperInput = new AssertionWrapper(createAssertion());

        sessionHandler.storeAssertion(session, assertionWrapperInput);

        AssertionWrapper assertionWrapperOutput = sessionHandler.getAssertion(assertionWrapperInput.getSessionIndex());
        Assertions.assertNotNull(assertionWrapperInput.getSessionIndex());
        Assertions.assertEquals(assertionWrapperInput.getAssertionAsBase64(), assertionWrapperOutput.getAssertionAsBase64());
    }

    @DisplayName("Test that no Assertion can be retrieved using unknown session index")
    @Test
    void testStoreAssertionGetUnknownSessionIndex() throws Exception {
        AssertionWrapper assertionWrapperOutput = sessionHandler.getAssertion("UNKNOWN_INDEX");
        Assertions.assertNull(assertionWrapperOutput);
    }

    @DisplayName("Test that stored Assertion is removed after timeout")
    @Test
    void testStoreAssertionTimeout() throws Exception {
        AssertionWrapper assertionWrapperInput = new AssertionWrapper(createAssertion());

        sessionHandler.storeAssertion(session, assertionWrapperInput);
        sessionHandler.cleanup(-1);

        AssertionWrapper assertionWrapperOutput = sessionHandler.getAssertion(session);
        Assertions.assertNull(assertionWrapperOutput);
    }

    @DisplayName("Test that stored Assertion is removed after timeout and can not be retrieved using session index")
    @Test
    void testStoreAssertionTimeoutSessionIndex() throws Exception {
        AssertionWrapper assertionWrapperInput = new AssertionWrapper(createAssertion());

        sessionHandler.storeAssertion(session, assertionWrapperInput);
        sessionHandler.cleanup(-1);

        AssertionWrapper assertionWrapperOutput = sessionHandler.getAssertion(assertionWrapperInput.getSessionIndex());
        Assertions.assertNotNull(assertionWrapperInput.getSessionIndex());
        Assertions.assertNull(assertionWrapperOutput);
    }

    @DisplayName("Test that stored Assertion can not be replayed")
    @Test
    void testStoreAssertionReplay() throws Exception {
        AssertionWrapper assertionWrapperInput = new AssertionWrapper(createAssertion());

        sessionHandler.storeAssertion(session, assertionWrapperInput);

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            sessionHandler.storeAssertion(session, assertionWrapperInput);
        });
        Assertions.assertEquals(String.format("Assertion with id '%s' and session index '%s' is already registered",assertionWrapperInput.getID(), assertionWrapperInput.getSessionIndex()), exception.getMessage());
    }

    @DisplayName("Test stored missing LogoutRequest will exit")
    @Test
    void testStoreLogoutRequestMissingLogoutRequest() throws Exception {

        sessionHandler.storeLogoutRequest(session, null);

        // Will never reach biz logic
        Mockito.verify(session, Mockito.never()).getId();
    }

    @DisplayName("Test that stored LogoutRequest can be retrieved")
    @Test
    void testStoreLogoutRequest() throws InitializationException, InternalException {
        LogoutRequestWrapper logoutRequestWrapperOldInput = new LogoutRequestWrapper(createLogoutRequest());
        LogoutRequestWrapper logoutRequestWrapperInput = new LogoutRequestWrapper(createLogoutRequest());

        // No output returned before
        LogoutRequestWrapper logoutRequestWrapperPreOutput = sessionHandler.getLogoutRequest(session);
        Assertions.assertNull(logoutRequestWrapperPreOutput);

        // input is persisted
        sessionHandler.storeLogoutRequest(session, logoutRequestWrapperOldInput);
        LogoutRequestWrapper logoutRequestWrapperOldOutput = sessionHandler.getLogoutRequest(session);
        Assertions.assertEquals(logoutRequestWrapperOldInput.getLogoutRequestAsBase64(), logoutRequestWrapperOldOutput.getLogoutRequestAsBase64());

        // input is replaced
        sessionHandler.storeLogoutRequest(session, logoutRequestWrapperInput);
        LogoutRequestWrapper logoutRequestWrapperOutput = sessionHandler.getLogoutRequest(session);
        Assertions.assertEquals(logoutRequestWrapperInput.getLogoutRequestAsBase64(), logoutRequestWrapperOutput.getLogoutRequestAsBase64());
    }

    @DisplayName("Test that stored LogoutRequest is removed after timeout")
    @Test
    void testStoreLogoutRequestTimeout() throws InternalException, InitializationException {
        LogoutRequestWrapper logoutRequestWrapperInput = new LogoutRequestWrapper(createLogoutRequest());

        sessionHandler.storeLogoutRequest(session, logoutRequestWrapperInput);
        sessionHandler.cleanup(-1);
        LogoutRequestWrapper logoutRequestWrapperOutput = sessionHandler.getLogoutRequest(session);

        Assertions.assertNull(logoutRequestWrapperOutput);
    }

    @DisplayName("Test that session id from the session is used in the in memory session handler")
    @Test
    void testGetSessionId() {
        Assertions.assertEquals(SESSION_ID, sessionHandler.getSessionId(session));
    }

    @DisplayName("Test that assertion is removed after logout")
    @Test
    void testLogout() throws Exception {
        AssertionWrapper assertionWrapperInput = new AssertionWrapper(createAssertion());

        sessionHandler.storeAssertion(session, assertionWrapperInput);
        sessionHandler.logout(session,assertionWrapperInput);

        AssertionWrapper assertionWrapperOutput = sessionHandler.getAssertion(session);
        Assertions.assertNull(assertionWrapperOutput);
    }

    @DisplayName("Test that assertion is removed after logout when assertion is wrong")
    @Test
    void testLogoutWrongAssertion() throws Exception {
        AssertionWrapper assertionWrapperWrong = new AssertionWrapper(createAssertion());
        AssertionWrapper assertionWrapperInput = new AssertionWrapper(createAssertion());

        sessionHandler.storeAssertion(session, assertionWrapperInput);

        AssertionWrapper assertionWrapperOutput = sessionHandler.getAssertion(session);
        Assertions.assertNotNull(assertionWrapperOutput);

        sessionHandler.logout(session,assertionWrapperWrong);

        AssertionWrapper assertionWrapperLogoutOutput = sessionHandler.getAssertion(session);
        Assertions.assertNull(assertionWrapperLogoutOutput);
    }

    @DisplayName("Test that assertions are removed from session and other session")
    @Test
    void testLogoutOfAssertionAndSession() throws Exception {
        AssertionWrapper assertionWrapperInputSession = new AssertionWrapper(createAssertion());
        AssertionWrapper assertionWrapperInput = new AssertionWrapper(createAssertion());

        HttpSession sessionUser = Mockito.mock(HttpSession.class);
        Mockito.when(sessionUser.getId()).thenReturn("USER_SESSION_ID");

        sessionHandler.storeAssertion(sessionUser, assertionWrapperInputSession);
        sessionHandler.storeAssertion(session, assertionWrapperInput);

        AssertionWrapper assertionWrapperOutput = sessionHandler.getAssertion(session);
        Assertions.assertNotNull(assertionWrapperOutput);

        AssertionWrapper assertionWrapperOutputSession = sessionHandler.getAssertion(sessionUser);
        Assertions.assertNotNull(assertionWrapperOutputSession);

        sessionHandler.logout(session,assertionWrapperInputSession);

        AssertionWrapper assertionWrapperLogoutOutput = sessionHandler.getAssertion(session);
        Assertions.assertNull(assertionWrapperLogoutOutput);

        AssertionWrapper assertionWrapperLogoutOutputSession = sessionHandler.getAssertion(sessionUser);
        Assertions.assertNull(assertionWrapperLogoutOutputSession);
    }

    @DisplayName("Test that assertion on one session is removed from another session after logout")
    @Test
    void testLogoutOtherSession() throws Exception {
        AssertionWrapper assertionWrapperInput = new AssertionWrapper(createAssertion());

        HttpSession sessionUser = Mockito.mock(HttpSession.class);
        Mockito.when(sessionUser.getId()).thenReturn("USER_SESSION_ID");

        sessionHandler.storeAssertion(sessionUser, assertionWrapperInput);

        AssertionWrapper assertionWrapperOutput = sessionHandler.getAssertion(sessionUser);
        Assertions.assertNotNull(assertionWrapperOutput);

        sessionHandler.logout(session,assertionWrapperInput);

        AssertionWrapper assertionWrapperLogoutOutput = sessionHandler.getAssertion(sessionUser);
        Assertions.assertNull(assertionWrapperLogoutOutput);
    }

    private Assertion createAssertion() throws Exception {
        AssertionService assertionService = new AssertionService();
        return assertionService.getAssertion(IdpUtil.createResponse(false, true, true,  "NAMEID", TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, UUID.randomUUID().toString()));
    }

    private AuthnRequest createAuthnRequest() throws InitializationException {
        AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
        return authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSIS_LEVEL, null);
    }

    private LogoutRequest createLogoutRequest() throws InitializationException {
        return IdpUtil.createLogoutRequest("NAMEID", NameID.PERSISTENT, TestConstants.IDP_LOGOUT_REQUEST_URL);
    }
}