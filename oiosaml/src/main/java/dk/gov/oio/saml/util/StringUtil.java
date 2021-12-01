package dk.gov.oio.saml.util;

import javax.servlet.http.HttpServletRequest;

public class StringUtil {

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

	public static String jsonEscape(String value) {
		StringBuilder sb = new StringBuilder();
		if (null != value) {
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
		}
		return sb.toString();
	}
}
