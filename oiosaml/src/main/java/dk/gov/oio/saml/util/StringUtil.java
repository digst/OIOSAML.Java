package dk.gov.oio.saml.util;

import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

/**
 * Utility class related to string operations in the OIOSAML library.
 */
public class StringUtil {

    /**
     * Constructs context path + page (URL) string, from the request,
     * by appending page to the context path.
     * @param request Servlet request
     * @param page page or context to append to the context path
     * @return Context path + page (URL)
     */
    public static String getUrl(HttpServletRequest request, String page) {
        String url = (request.getContextPath() != null) ? request.getContextPath() : "/";

        int slashCount = (url.endsWith("/")) ? 1 : 0;
        slashCount += (page != null && page.startsWith("/")) ? 1 : 0;

        switch (slashCount) {
            case 0:
                url += "/" + ((page != null) ? page : "");
                break;
            case 1:
                url += ((page != null) ? page : "");
                break;
            case 2:
                url += ((page != null) ? page.substring(1) : "");
                break;
        }
        
        return url;
    }

    /**
     * Create string representation of XML element.
     *
     * @param element Any XML element
     * @return XML is parsed to string, if this fails null is returned
     */
    public static String elementToString(Element element) {
        try {
            Source source = new DOMSource(element);
            TransformerFactory transFactory = TransformerFactory.newInstance();
            Transformer transformer = transFactory.newTransformer();
            StringWriter buffer = new StringWriter();

            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.transform(source, new StreamResult(buffer));

            return buffer.toString();
        }
        catch (Exception ex) {
            return null;
        }
    }

    /**
     * Return an escaped value for use in a json document.
     * @param value input value with special characters
     * @return json escaped output value, an empty string if value is null.
     */
    public static String jsonEscape(String value) {
        StringBuilder sb = new StringBuilder();
        if (null == value) {
            return "";
        }
        for (char ch : value.toCharArray()) {
            switch (ch) {
                case '"':
                case '\\':
                    sb.append("\\").append(ch);
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                default:
                    if (ch <= 0x1F | ch == '\u2028' | ch == '\u2029') {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
            }
        }
        return sb.toString();
    }

    /**
     * Check if input string is empty
     * @param input any string
     * @return true if input string is null, empty or only contain whitespaces
     */
    public static boolean isEmpty(String input) {
        if (null == input || input.trim().isEmpty()) {
            return true;
        }
        return false;
    }

    /**
     * Check if input string is not empty
     * @param input any string
     * @return false if input string is null, empty or only contain whitespaces otherwise true
     */
    public static boolean isNotEmpty(String input) {
        return !isEmpty(input);
    }

    /**
     * Return default string if input string is empty
     * @param input any string
     * @param defaultString string to return if input is empty
     * @return input unless input string is null, empty or only contain whitespaces, then return default string
     */
    public static String defaultIfEmpty(String input, String defaultString) {
        if (null == input || input.trim().isEmpty()) {
            return defaultString;
        }
        return input;
    }
}
