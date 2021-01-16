<!doctype html>
<html>
<head>
    <title>Custom error page</title>
</head>
<body>

<h3>Custom error page</h3>
<p>An error occurred, which could not be handled.</p>

<h3>
<%= session.getAttribute("oiosaml.error.type") %>
</h3>
<p>
<%= session.getAttribute("oiosaml.error.message") %>
</p>

<a href="index.jsp">Go back to frontpage</a>

</body>
</html>