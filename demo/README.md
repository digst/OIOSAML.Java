This is the demo application for OIOSAML.

It shows how to use the OIOSAML library, and comes pre-configured and ready to run.

1. The oiosaml-config folder contains the configuration for the application. In an ordinary use-case, the OIOSAML library will create this folder and the files within, when the application is bootstrapped.

2. The source folder contains a basic webapp, with the following files

 webapp
  ├── configure.jsp
  ├── head.jsp
  ├── index.jsp
  ├── oiosaml.gif
  ├── postlogin.jsp
  ├── sp
  │   ├── logout.jsp
  │   ├── post.jsp
  │   ├── priv1.jsp
  │   └── query.jsp
  └── WEB-INF
      ├── classes
      │   └── log4j.properties
      └── web.xml


- configure.jsp shows the current configuration of OIOSAML, and allows tweaking certain settings on runtime
- index.jsp is the landing page, and contains links to trigger login/logout
- sp/priv1.jsp is a secured page, and accessing it requires that the user is logged in - it will display all information known about the logged-in user

3. Running the application can be done using the Tomcat plugin for maven - simply execute the following two commands (the first to compile the project)

$ mvn clean install
$ mvn tomcat7:run-war

4. Accessing the running application can be done at this location - the demo application uses a self-signed certificate, so you may encounter an SSL warning

https://localhost:8443/oiosaml2-demo.java/

5. You will need a TEST-MOCES certificate to perform a login. A sample MOCES certificate has been supplied (test-moces.pfx), with the password 'Test1234'
