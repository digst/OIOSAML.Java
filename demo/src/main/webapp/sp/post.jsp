<!-- "$Id: priv1.jsp 3040 2008-06-23 15:34:36Z jre $"; -->
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertionHolder"%>
<%@page import="dk.itst.oiosaml.sp.service.util.Utils"%>
<%@page import="dk.itst.oiosaml.sp.util.AttributeUtil"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertion"%>
<%@page import="dk.itst.oiosaml.sp.UserAttribute"%>

    <jsp:include page="/head.jsp" />

<h1>Received request</h1>

<table border="0">

<tr><td>Method:</td><td><%= request.getMethod() %></td></tr>
<tr><td colspan="2">Parameters:</td></tr>

<%

for (Iterator<?> i = request.getParameterMap().entrySet().iterator(); i.hasNext(); ) {
	Map.Entry<String, String[]> e = (Map.Entry<String, String[]>)i.next();
	
	for (String val : e.getValue()) {
		%>
		<tr><td><%= e.getKey() %>:</td><td><%= val %></td></tr>
	<%
	}
}
%>

</table>

  </body>

<%@page import="java.util.Map"%>
<%@page import="java.util.Iterator"%></html>
