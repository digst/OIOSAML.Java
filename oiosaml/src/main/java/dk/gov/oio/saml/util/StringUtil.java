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
}
