<!-- "$Id: index.jsp 2978 2008-06-10 07:39:19Z jre $"; -->
<%@page import="dk.itst.oiosaml.configuration.SAMLConfigurationFactory"%>
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="org.apache.commons.configuration.Configuration"%>
<%@page import="java.util.Iterator"%>
    <jsp:include page="head.jsp" />
    <h1>Runtime configuration - OIOSAML.java Service Provider Demo</h1>
	<p>Use this to change the OIOSAML.java runtime configuration. Changes here are lost when the server is restarted. See <a href="docs/configuration.html">the documentation</a> for configuration help.</p>

<%

CompositeConfiguration conf = (CompositeConfiguration) SAMLConfigurationFactory.getConfiguration().getSystemConfiguration();
StringWriter sw = new StringWriter();
PropertiesConfiguration c = null;

for (int i = 0; i < conf.getNumberOfConfigurations(); i++){
	if (conf.getConfiguration(i) instanceof PropertiesConfiguration) {
		c = (PropertiesConfiguration)conf.getConfiguration(i);
		break;
	}
}

if (request.getMethod().equals("POST") && c != null) {
	c.setProperty(Constants.PROP_PASSIVE, Boolean.valueOf(request.getParameter("isPassive")));
	c.setProperty(Constants.PROP_PASSIVE_USER_ID, request.getParameter("passiveUsername"));
	c.setProperty(Constants.PROP_FORCE_AUTHN_URLS, request.getParameter("forceAuthn") != null ? "/.*" : null);
	c.setProperty(Constants.PROP_NAMEID_POLICY_ALLOW_CREATE, Boolean.valueOf(request.getParameter("allowCreate")));
	c.setProperty(Constants.PROP_NAMEID_POLICY, request.getParameter("nameIdPolicy"));
	
	if (request.getParameter("property") != null && !request.getParameter("property").trim().equals("")) {
		c.setProperty(request.getParameter("property"), request.getParameter("propertyValue"));
	}
}


c.save(sw);
%>

<form method="post">

<table border="0">
<tr><td>IsPassive</td><td><input type="checkbox" name="isPassive" value="true" <%=  conf.getBoolean(Constants.PROP_PASSIVE, false) ? "checked='checked'" : "" %>/></td></tr>
<tr><td>Passive username</td><td><input type="text" name="passiveUsername" value="<%=  conf.getString(Constants.PROP_PASSIVE_USER_ID, "") %>" /></td></tr>
<tr><td>Force authn</td><td><input type="checkbox" name="forceAuthn" value="true" <%=  conf.getString(Constants.PROP_FORCE_AUTHN_URLS, null) == null ? "" : "checked='checked'" %> /></td></tr>
<tr><td>Allow create</td><td><input type="checkbox" name="allowCreate" value="true" <%=  conf.getBoolean(Constants.PROP_NAMEID_POLICY_ALLOW_CREATE, false) ? "checked='checked'" : "" %> /></td></tr>
<tr><td>NameID Policy (blank, persistent or transient)</td><td><input type="text" name="nameIdPolicy" value="<%=  conf.getString(Constants.PROP_NAMEID_POLICY, "") %>" /></td></tr>
<tr><td><input type="text" name="property" /></td><td><input type="text" name="propertyValue" /></td></tr>
</table>
<input type="submit" value="Set configuration" />
</form>

<h3>Current configuration - from <%= c.getFile() %></h3>
<pre>
<%= sw %>
</pre>


  </body>





<%@page import="org.apache.commons.configuration.CompositeConfiguration"%>
<%@page import="org.apache.commons.configuration.PropertiesConfiguration"%>
<%@page import="java.io.StringWriter"%>
<%@page import="dk.itst.oiosaml.sp.service.util.Constants"%></html>