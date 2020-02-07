<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<!-- "$Id: index.jsp 2557 2008-04-14 13:49:34Z rolf $"; -->
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta http-equiv="Expires" content="0" />
    <title>OIOSAML.java Default login page for HTTP Post method</title>
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
    <h1>Default login page for HTTP Post method.</h1>
	<form name="loginform" action="<%= (String)request.getAttribute("action") %>" method="post">
	<input type="hidden" name="SAMLRequest" value="<%=(String) request.getAttribute("SAMLRequest") %>" />
	<input type="hidden" name="RelayState" value="<%= (String)request.getAttribute("RelayState") %>" />
	<input type="submit" name="submit" value="Click here to submit form to IdP server" />
	</form>
	<p>This page is the default OIOSaml.java HTTP POST method login page.</p>
	<p>Submitting the form will send the following values to the IdP:</p>
	<table>
	<tr><td>action</td><td><code><%= (String)request.getAttribute("action") %></code></td></tr>
	<tr><td>SAMLRequest</td><td><code><%= (String)request.getAttribute("SAMLRequest") %></code></td></tr>
	<tr><td>RelayState</td><td><code><%= (String)request.getAttribute("RelayState") %></code></td></tr>
	</table> 
	
	<div><img src="<%= request.getContextPath() %>/oiosaml.gif" alt="oiosaml.java" /></div>
  </body>
</html>