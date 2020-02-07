<!-- "$Id: priv1.jsp 3040 2008-06-23 15:34:36Z jre $"; -->
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertionHolder"%>
<%@page import="dk.itst.oiosaml.sp.service.util.Utils"%>
<%@page import="dk.itst.oiosaml.sp.util.AttributeUtil"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertion"%>
<%@page import="dk.itst.oiosaml.sp.UserAttribute"%>
<%@page import="dk.itst.oiosaml.sp.service.util.Constants"%>

	<% UserAssertion ua = UserAssertionHolder.get(); %>

    <jsp:include page="/head.jsp" />
    <div style="float: left">
    <h1>User NameID</h1>
    <%= ua.getSubject() %>
    
    <h1>Attributes on UserAssertion</h1>
    <ul>
    <% 
    for (UserAttribute a : ua.getAllAttributes()) {
    	%><li><%= Utils.makeXML(a.toString()) %></li><%
    }
    %>
    </ul>
    
    <p>
    Authenticated: <%= ua.isAuthenticated() %><br />
    Assertion signed: <%= ua.isSigned() %><br />
    SAML Profile: <%= ua.isOIOSAMLCompliant() %><br />
    OCES Attribute Profile: <%= ua.isOCESProfileCompliant() %><br />
    Persistent Pseudonym Profile: <%= ua.isPersistentPseudonymProfileCompliant() %><br />
     
    </p>
    <a href="query.jsp">Perform attribute query</a> &nbsp; <a href="logout.jsp">Local logout</a> &nbsp; <a href="<%= request.getRequestURL() %>?<%= Constants.QUERY_STRING_FORCE_AUTHN %>=True">Force login</a><br />
    </div>
	<div style="float: right"><img src="<%= request.getContextPath() %>/oiosaml.gif" alt="oiosaml.java" /></div>
	<div style="clear: both">&nbsp;</div>
    <h1>Assertion:</h1><span style="font-size:80%; font-family:Monospace;">
    <%= Utils.beautifyAndHtmlXML(UserAssertionHolder.get().getXML(), "&nbsp;&nbsp;&nbsp;&nbsp;") %>
  </span>
  
  <br />
  <% if (!UserAssertionHolder.get().isAuthenticated()) { %>
  <a href="<%= request.getContextPath() %>/saml/login">Force login</a><br />
  <% } %>
  
  </body>
</html>
