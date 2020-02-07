package dk.itst.oiosaml.sp.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.service.util.HttpSOAPClient;

public class HttpSOAPClientTest extends AbstractTests {
	private DummyServer ds;
	private HttpSOAPClient client;

	@Before
	public void setUp() throws IOException {
		ds = new DummyServer();
		client = new HttpSOAPClient();
		new Thread(ds).start();
	}
	
	@After
	public void tearDown() {
		try {
			ds.ss.close();
		} catch (IOException e) {}
	}
	
	@Test
	public void testArtifactResolve() throws Exception {
		ArtifactResolve ar = SAMLUtil.buildXMLObject(ArtifactResolve.class);
		
		Envelope env = client.wsCall(ar, "http://localhost:12349", "test", "test", true);
		assertTrue(env.getBody().getUnknownXMLObjects().get(0) instanceof ArtifactResponse);
		assertEquals("\"http://www.oasis-open.org/committees/security\"", ds.headers.get("SOAPAction"));
		
		assertEquals("test:test", new String(Base64.decode(ds.headers.get("Authorization").split(" ")[1]), "UTF-8"));
	}

	@Test
	public void dontFailWhenUsingLongUsernamePassword() throws Exception {
		ArtifactResolve ar = SAMLUtil.buildXMLObject(ArtifactResolve.class);
		
		client.wsCall(ar, "http://localhost:12349", "test123456789012345678901234567890", "test123456789012345678901234567890", true);
	}
	
	private static class DummyServer implements Runnable {
		private ServerSocket ss;
		private HashMap<String, String> headers;

		public DummyServer() throws IOException {
			ss = new ServerSocket(12349);
		}

		public void run() {
			try {
				
				Socket client = ss.accept();
				BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
				
				StringBuilder sb = new StringBuilder();
				String line = null;
				
				headers = new HashMap<String, String>();
				while ((line = in.readLine()) != null) {
					if ("".equals(line.trim())) {
						for (int i = 0; i < Integer.parseInt(headers.get("Content-Length")); i++) {
							sb.append((char)in.read());
						}
						break;
					}
					String[] h = line.split(": ");
					if (h.length == 2) {
						headers.put(h[0], h[1]);
					}
				}
				PrintWriter pw = new PrintWriter(client.getOutputStream());
				pw.println("HTTP/1.1 200 OK");
				pw.println("Server: test");
				pw.println();

				Envelope env = SAMLUtil.buildXMLObject(Envelope.class);
				Body body = SAMLUtil.buildXMLObject(Body.class);
				env.setBody(body);
				body.getUnknownXMLObjects().add(SAMLUtil.buildXMLObject(ArtifactResponse.class));
				pw.println(XMLHelper.nodeToString(SAMLUtil.marshallObject(env)));
				pw.close();
				
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}

}
