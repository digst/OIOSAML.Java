OIOSAML.java is distributed under the Mozilla Public License 1.1, and is based on OpenSAML 2.0, which is released under the Apache License 2.0.

See docs/index.html for full documentation, including installation
instructions.

Building and packaging the project:
 
- Download and install latest Java SDK 6
- Set environment variable JAVA_HOME to installation dir of SDK 6
- Download and install groovy-2.1.6-installer.exe and include GANT in the installation. Hereafter set the environment variable GROOVY_HOME to the installation dir and include %GROOVY_HOME%\bin in the path. This will install a working version of GANT 1.9.9 (I did not succed in downloading and installing GANT manually. I tried many different versions (1.9.2, 1.9.5 and 1.9.9). Also I tried the GANT versions where Groovy must be manually installed.)
- Download and install JCE in order for the tests to succeed
- Run gant build_everything. Also, run this command before opening the project in an IDE in order to have the dependant jars downloaded.
 
Setting up demo application:
- Download Tomcat (e.g. 7.0.42) and set the environment variable CATALINA_HOME to the folder where you unpacked Tomcat. Optionally add %CATALINA_HOME%\bin to the path for easier startup and shutdown of Tomcat.

Uncomment connector on port 8080 and insert the connector below in %CATALINA_HOME%\conf\server.xml

-------------------------------------------------------------------------------------------------------------------------------------
	<!--
		Tomcat can use two different implementations of SSL:

		- the JSSE implementation provided as part of the Java runtime (since 1.4)
		- the APR implementation, which uses the OpenSSL engine by default.

		APR implementation is used as default but we need the JSSE implementation.
		We need to set protocol="org.apache.coyote.http11.Http11NioProtocol" in order to use the JSSE implementation.
		org.apache.coyote.http11.Http11NioProtocol is used over org.apache.coyote.http11.Http11Protocol to allow for better performance.
	-->
    <Connector port="443" 
			   protocol="org.apache.coyote.http11.Http11NioProtocol"
			   SSLEnabled="true"
			   maxThreads="150" 
			   scheme="https" 
			   secure="true"
			   clientAuth="false" sslProtocol="TLS" 
			   keystoreFile="Path to SSL certificate" 
			   keystorePass="S0lskin"
			   keystoreType="PKCS12"/>
-------------------------------------------------------------------------------------------------------------------------------------

- Insert the following in the <host> element %CATALINA_HOME%\conf\server.xml. This makes the oiosaml.java demo application available at the root path and makes the Tomcat manager available at /Tmgr path.

-------------------------------------------------------------------------------------------------------------------------------------
	<Context path="" docBase="oiosaml.java-demo" reloadable="true"/>
	<Context path="Tmgr" docBase="ROOT" reloadable="true"/>
-------------------------------------------------------------------------------------------------------------------------------------

Quick start:
 - Unzip oiosaml.java-sp-demo-*.war and edit WEB-INF/web.xml
 - Set oiosaml-j.home to point to an empty directory. It will be created if it does not exist.
 - Zip the files back into a war file and rename it to oiosaml.java-sp-demo
 - Deploy the war to a servlet container like Apache Tomcat
 - Open a browser and access the deployed application on https://localhost
 - Click on the Configure link to configure the system



