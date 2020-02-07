<!-- "$Id: priv1.jsp 2952 2008-05-28 13:18:37Z jre $"; -->
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="dk.itst.oiosaml.sp.service.util.Utils"%>
<%@page import="dk.itst.oiosaml.sp.util.AttributeUtil"%>
<%@page import="dk.itst.oiosaml.sp.UserAttributeQuery"%>
<%@page import="dk.itst.oiosaml.sp.UserAttribute"%>
<%@page import="java.util.*"%>

    <jsp:include page="/head.jsp" />

<h2>Perform attribute query</h2>

<form method="get">
<table border="0">
<tr><td>NameID:</td><td><input type="text" name="nameId" /></td></tr>
<tr><td>Attribute:</td><td><input type="text" name="attribute" /></td><td>Format: </td><td><input type="text" name="format" /></td></tr>
<tr><td>Attribute:</td><td><input type="text" name="attribute" /></td><td>Format: </td><td><input type="text" name="format" /></td></tr>
<tr><td>Attribute:</td><td><input type="text" name="attribute" /></td><td>Format: </td><td><input type="text" name="format" /></td></tr>
<tr><td>Attribute:</td><td><input type="text" name="attribute" /></td><td>Format: </td><td><input type="text" name="format" /></td></tr>
<tr><td colspan="2"><input type="submit" value="Perform attribute query"/></td></tr>
</table>
</form>

<%

if (request.getParameter("nameId") != null) {
	%>
	<h3>Attributes</h3>
	<table border="0">
	<tr><td><strong>Attribute</strong></td><td><strong>Value</strong></td></tr><%
	UserAttributeQuery aq = new UserAttributeQuery();
	
	List<UserAttribute> names = new ArrayList<UserAttribute>();
	String[] reqnames = request.getParameterValues("attribute");
	for (int i = 0; i < reqnames.length; i++) {
		if (reqnames[i] != null && !"".equals(reqnames[i])) {
			names.add(UserAttribute.create(reqnames[i], request.getParameterValues("format")[i]));
		}
	}
	UserAssertion ua = (UserAssertion)session.getAttribute(Constants.SESSION_USER_ASSERTION);
	
	Collection<UserAttribute> attrs = aq.query(request.getParameter("nameId"), ua.getNameIDFormat(), names.toArray(new UserAttribute[0]));
	
	for (UserAttribute attr: attrs) {
		%><tr><td><%= attr.getName() %></td><td><%= attr.getValue() %></td></tr><%
	}
	%></table><%
}

%>
      
  </body>

<%@page import="dk.itst.oiosaml.sp.UserAssertion"%>
<%@page import="dk.itst.oiosaml.sp.service.util.Constants"%></html>