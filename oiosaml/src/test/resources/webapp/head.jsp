<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta http-equiv="Expires" content="0" />
    <title>OIOSAML.java demo application</title>
            <style type="text/css">
    	body {background-color: white; margin: 20px;}
    	body, tr, td {font-family: Verdana, Helvetica, sans-serif; color: #456974;}
    	div#pagecontainer {width: 80%;}
    	h1, h2, h3, h4 {color: #76c2bc; border-bottom: 1px solid #76c2bc;}
    	.monospace {font-family: monospace;}
    	legend {font-weight: bold;}
    	fieldset {margin-top: 10px; margin-bottom: 10px;}
    	span.emphasis {font-weight: bold;}
    </style>
  </head>
<body>
<%@page import="dk.itst.oiosaml.configuration.SAMLConfigurationFactory"%>
<%@page import="org.apache.commons.configuration.Configuration"%>
<%@page import="dk.itst.oiosaml.sp.service.util.Constants"%>
<%@page import="dk.itst.oiosaml.sp.UserAssertion"%>

<a href="<%=request.getContextPath()%>">Home</a>
<%
	try {
	SAMLConfigurationFactory.getConfiguration().getSystemConfiguration(); 
	UserAssertion ua = (UserAssertion)session.getAttribute(Constants.SESSION_USER_ASSERTION);
%>
<%=ua != null && ua.isAuthenticated() ? "<a href=\"" + request.getContextPath() + "/saml/Logout\">Log out</a>" : "<a href=\"" + request.getContextPath() + "/saml/login\">Login</a>"%>

<a href="<%= request.getContextPath() %>/saml/metadata">Metadata</a>

<% } catch (RuntimeException e) { %>
<h2>System is not configured</h2>
<a href="saml/configure">Configure the system here</a>.
<% } %>
<a href="<%= request.getContextPath() %>/docs/index.html">OIOSAML.java Documentation</a>