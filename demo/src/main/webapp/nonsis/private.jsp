<%@page import="dk.gov.oio.saml.session.AssertionWrapperHolder"%>
<%@page import="dk.gov.oio.saml.session.AssertionWrapper"%>
<!doctype html>
<html>
<head>
    <title>No NSIS Page</title>
</head>
<body>
<a href="../saml/logout">Logout</a>
<br/>
<a href="../index.jsp">Go back to frontpage</a>

<h3>Assertion Content</h3>
<% AssertionWrapper wrapper = AssertionWrapperHolder.get(); %>

<pre>
Issue = <%= wrapper.getIssuer() %>
Subject/NameID = <%= wrapper.getSubjectNameId() %>
NSIS Level = <%= wrapper.getNsisLevel() %>
AssuranceLevel = <%= wrapper.getAssuranceLevel() %>

Attributes = <%= wrapper.getAttributeValues() %>
</pre>

<h3>Assertion XML</h3>
<pre>
<%= wrapper.getAssertionAsHtml() %>
</pre>

</body>
</html>