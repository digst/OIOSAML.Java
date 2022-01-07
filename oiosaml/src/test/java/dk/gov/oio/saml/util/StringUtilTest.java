package dk.gov.oio.saml.util;

import dk.gov.oio.saml.model.NSISLevel;
import dk.gov.oio.saml.service.AuthnRequestService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.w3c.dom.*;

import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

class StringUtilTest {

    @DisplayName("Test that URL consist of servlet context + page input")
    @Test
    void testGetUrl() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getContextPath()).thenReturn("/test/123");

        Assertions.assertEquals("/test/123/hello/1.jsp", StringUtil.getUrl(request, "/hello/1.jsp"));
        Assertions.assertEquals("/test/123/hello/2.jsp", StringUtil.getUrl(request, "hello/2.jsp"));
    }

    @DisplayName("Test that empty URL consist of servlet '/' + page input")
    @Test
    void testEmptyGetUrl() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getContextPath()).thenReturn("");

        Assertions.assertEquals("/hello/1.jsp", StringUtil.getUrl(request, "/hello/1.jsp"));
        Assertions.assertEquals("/hello/2.jsp", StringUtil.getUrl(request, "hello/2.jsp"));
    }

    @DisplayName("Test that elementToString return XML string with valid content")
    @Test
    void testElementToString() throws Exception {
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        String inResponseToId = UUID.randomUUID().toString();
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
        Element element = XMLObjectSupport.marshall(messageContext.getMessage());

        String xml =  StringUtil.elementToString(element);

        Assertions.assertTrue(xml.contains("InResponseTo=\"" + inResponseToId + "\""));
        Assertions.assertTrue(xml.contains("Destination=\"" + TestConstants.SP_ASSERTION_CONSUMER_URL + "\""));
    }

    @DisplayName("Test that input string is JSON escaped after running jsonEscape")
    @Test
    void testJsonEscape() {
        Assertions.assertEquals("\\\\t\\t\\b\\r\\n\\f\\\"\\\\TEST\\u2028\\t\u9515", StringUtil.jsonEscape("\\t\t\b\r\n\f\"\\TEST\u2028\u0009\u9515"));
    }

    @DisplayName("Test that isEmpty return true on null and blank string and otherwise false")
    @Test
    void testIsEmpty() {
        Assertions.assertTrue(StringUtil.isEmpty(null));
        Assertions.assertTrue(StringUtil.isEmpty(""));
        Assertions.assertTrue(StringUtil.isEmpty("  "));
        Assertions.assertFalse(StringUtil.isEmpty("TEST"));
    }

    @DisplayName("Test that isNotEmpty return false on null and blank string and otherwise true")
    @Test
    void testIsNotEmpty() {
        Assertions.assertFalse(StringUtil.isEmpty(null));
        Assertions.assertFalse(StringUtil.isEmpty(""));
        Assertions.assertFalse(StringUtil.isEmpty("  "));
        Assertions.assertTrue(StringUtil.isEmpty("TEST"));
    }

    @DisplayName("Test that defaultIfEmpty return defaultIfEmpty on null and blank string and otherwise input value")
    @Test
    void testDefaultIfEmpty() {
        String DEFAULT = "DEFAULT";
        Assertions.assertEquals(DEFAULT, StringUtil.defaultIfEmpty(null, DEFAULT));
        Assertions.assertEquals(DEFAULT, StringUtil.defaultIfEmpty("", DEFAULT));
        Assertions.assertEquals(DEFAULT, StringUtil.defaultIfEmpty("  ", DEFAULT));
        Assertions.assertEquals("TEST", StringUtil.defaultIfEmpty("TEST", DEFAULT));
    }

    @DisplayName("Test that we can serialize OPENSAML object to string and back to OPENSAML object")
    @Test
    void testXMLObjectToBase64() throws Exception {
        // Create AuthnRequest
        AuthnRequestService authnRequestService = AuthnRequestService.getInstance();
        AuthnRequest authnRequest = authnRequestService.createAuthnRequest(TestConstants.SP_ASSERTION_CONSUMER_URL, false, false, NSISLevel.SUBSTANTIAL);
        String inResponseToId = authnRequest.getID();

        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, false, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
        Assertion assertionInput = (Assertion) messageContext.getMessage();

        String base64Input = StringUtil.xmlObjectToBase64(assertionInput);

        Assertion assertionOutput = (Assertion) StringUtil.base64ToXMLObject(base64Input);
        Assertions.assertEquals(assertionOutput, assertionInput);
        Assertions.assertEquals(assertionOutput.getID(), assertionInput.getID());
        Assertions.assertEquals(assertionOutput.getNoNamespaceSchemaLocation(), assertionInput.getNoNamespaceSchemaLocation());
        Assertions.assertEquals(assertionOutput.getSchemaLocation(), assertionInput.getSchemaLocation());
        Assertions.assertEquals(assertionOutput.getSignatureReferenceID(), assertionInput.getSignatureReferenceID());
        Assertions.assertEquals(assertionOutput.getVersion(), assertionInput.getVersion());
        Assertions.assertEquals(assertionOutput.getClass().getName(), assertionInput.getClass().getName());

        String base64Output = StringUtil.xmlObjectToBase64(assertionOutput);
        Assertions.assertEquals(base64Output, base64Input);
    }
}