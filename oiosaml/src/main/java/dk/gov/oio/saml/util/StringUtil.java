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
}
