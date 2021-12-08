package dk.gov.oio.saml.filter;

import dk.gov.oio.saml.util.StringUtil;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class SameSiteFilter implements Filter {
	private static final String SAMESITE_COOKIE_HEADER = "Set-Cookie";
	private static final String SAMESITE_ATTRIBITE_NAME = "SameSite";
	private static final String SAMESITE_NONE_VALUE = "None";

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void destroy() {
    }

    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
        if (response instanceof HttpServletResponse) {
            chain.doFilter(request, new SameSiteWrapper((HttpServletResponse) response));
        }
        else {
        	chain.doFilter(request, response);
        }
    }
    
    private class SameSiteWrapper extends HttpServletResponseWrapper {
    	private HttpServletResponse response;
        
        public SameSiteWrapper(HttpServletResponse resp) {
            super(resp);

            response = resp;
        }
        
        @Override
        public void sendError(int sc) throws IOException {
            fixSameSiteCookies();

            super.sendError(sc);
        }
        
        @Override
        public PrintWriter getWriter() throws IOException {
        	fixSameSiteCookies();

            return super.getWriter();
        }
        
        @Override
        public void sendError(int sc, String msg) throws IOException {
        	fixSameSiteCookies();

            super.sendError(sc, msg);
        }
        
        @Override
        public void sendRedirect(String location) throws IOException {
        	fixSameSiteCookies();

            super.sendRedirect(location);
        }
        
        @Override
        public ServletOutputStream getOutputStream() throws IOException {
        	fixSameSiteCookies();

            return super.getOutputStream();
        }
        
        private void fixSameSiteCookies() {
            Collection<String> headers = response.getHeaders(SAMESITE_COOKIE_HEADER);
            if (headers == null || headers.size() == 0) {
            	return;
            }

            boolean firstCookie = true;
            for (String header : headers) {
                if (StringUtil.isEmpty(header)) {
                    continue;
                }

                if (!header.contains(SAMESITE_ATTRIBITE_NAME)) {
                    header = header + ";" + SAMESITE_ATTRIBITE_NAME + "=" + SAMESITE_NONE_VALUE;                
                } 

                // overwrite existing cookies on first run, then append the new ones
                if (firstCookie) {
                    response.setHeader(SAMESITE_COOKIE_HEADER, header);
                }
                else {
                    response.addHeader(SAMESITE_COOKIE_HEADER, header);
                }

                firstCookie = false;
            }
        }
    }
}