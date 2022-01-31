package dk.gov.oio.saml.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.w3c.dom.*;

import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

class StringUtilTest {

    @DisplayName("Test that URL consist of servlet context + page input")
    @Test
    void testGetUrl() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getContextPath()).thenReturn("/test/123");
        String page = "/hello/hello.jsp";

        String url = StringUtil.getUrl(request, page);

        Assertions.assertEquals("/test/123/hello/hello.jsp", url);
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
        Assertions.assertEquals("\\t\\b\\r\\n\\f\\\"\\\\TEST\\u2028\\t\u9515", StringUtil.jsonEscape("\t\b\r\n\f\"\\TEST\u2028\u0009\u9515"));
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
        Assertions.assertFalse(StringUtil.isNotEmpty(null));
        Assertions.assertFalse(StringUtil.isNotEmpty(""));
        Assertions.assertFalse(StringUtil.isNotEmpty("  "));
        Assertions.assertTrue(StringUtil.isNotEmpty("TEST"));
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
}