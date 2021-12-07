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

    @DisplayName("Test that URL is created correctly")
    @Test
    void getUrl() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getContextPath()).thenReturn("/test/123");
        String page = "/hello/hello.jsp";

        String url = StringUtil.getUrl(request, page);

        Assertions.assertEquals("/test/123/hello/hello.jsp", url);
    }

    @Test
    void elementToString() throws Exception {
        String nameID = "https://data.gov.dk/model/core/eid/person/uuid/37a5a1aa-67ce-4f70-b7c0-b8e678d585f7";
        String inResponseToId = UUID.randomUUID().toString();
        MessageContext<SAMLObject> messageContext = IdpUtil.createMessageWithAssertion(true, true, true,  nameID, TestConstants.SP_ENTITY_ID, TestConstants.SP_ASSERTION_CONSUMER_URL, inResponseToId);
        Element element = XMLObjectSupport.marshall(messageContext.getMessage());

        String xml =  StringUtil.elementToString(element);

        Assertions.assertTrue(xml.contains("InResponseTo=\"" + inResponseToId + "\""));
        Assertions.assertTrue(xml.contains("Destination=\"" + TestConstants.SP_ASSERTION_CONSUMER_URL + "\""));
    }

    @Test
    void jsonEscape() {
        Assertions.assertEquals("\\t\\b\\r\\n\\f\\\"\\\\TEST\\u2028\\t\u9515", StringUtil.jsonEscape("\t\b\r\n\f\"\\TEST\u2028\u0009\u9515"));
    }
}