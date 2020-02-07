package dk.itst.oiosaml.sp.service.session;

import javax.servlet.http.HttpSession;

public interface SameSiteSessionSynchronizer {
	public HttpSession getSession(String requestId);
	public void linkSession(String requestId, String sessionId);
}
