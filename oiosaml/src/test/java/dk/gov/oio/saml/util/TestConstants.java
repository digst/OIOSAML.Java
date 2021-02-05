package dk.gov.oio.saml.util;

public class TestConstants {
	public static final String SP_ENTITY_ID = "http://sp.localhost";
	public static final String SP_BASE_URL = "http://localhost:8080";
	public static final String SP_ASSERTION_CONSUMER_URL = "http://localhost:8080/saml/assertionConsumer";
	public static final String SP_LOGOUT_REQUEST_URL = "http://localhost:8080/saml/logout";
	public static final String SP_LOGOUT_RESPONSE_URL = "http://localhost:8080/saml/logout/response";

	public static final String IDP_ENTITY_ID = "http://mockidp.localhost";
	public static final String IDP_METADATA_URL = "http://localhost:8081/saml/metadata";
	public static final String IDP_LOGOUT_REQUEST_URL = "http://localhost:8081/saml/logout";

	public static final String IDP_METADATA = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"077ae9ba-e94a-3ced-89a7-ddf7638bccf5\" entityID=\"http://mockidp.localhost\">\n" +
			"    <md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
			"        <md:KeyDescriptor use=\"signing\">\n" +
			"            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
			"                <ds:X509Data>\n" +
			"                    <ds:X509Certificate>MIID3zCCAsegAwIBAgIUb0xgAHok8te7sBj3lXiOrXpLv9kwDQYJKoZIhvcNAQEL\n" +
			"BQAwfzELMAkGA1UEBhMCREsxEDAOBgNVBAgMB0Rlbm1hcmsxEzARBgNVBAcMCkNv\n" +
			"cGVuaGFnZW4xITAfBgNVBAoMGERpZ2l0YWxpc2VyaW5nc3N0eXJlbHNlbjEQMA4G\n" +
			"A1UECwwHT0lPU0FNTDEUMBIGA1UEAwwLT0lPU0FNTCBJRFAwHhcNMjAxMjI4MDk0\n" +
			"MjAzWhcNMzAxMjI2MDk0MjAzWjB/MQswCQYDVQQGEwJESzEQMA4GA1UECAwHRGVu\n" +
			"bWFyazETMBEGA1UEBwwKQ29wZW5oYWdlbjEhMB8GA1UECgwYRGlnaXRhbGlzZXJp\n" +
			"bmdzc3R5cmVsc2VuMRAwDgYDVQQLDAdPSU9TQU1MMRQwEgYDVQQDDAtPSU9TQU1M\n" +
			"IElEUDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO50DYKJnT1p6I7T\n" +
			"WQzWEnhGDOJSNtovch4yBsHgrt4G2FRkor5V4wbteyXpmZ8kTqcrGymwwewhHdSR\n" +
			"NP4GxLRPp0eBpPuCJfXp4zkpkNnnJ0FoxU5AQD9bMNmdM4bl/P8L7diPOIkaOK/+\n" +
			"cIZhC6QDwP4azskqI6iWm9QFREH/MBezeQEIpseM6/ARlJUdH0rlsxr/w33H7nBh\n" +
			"pEk1TE2PxBhSpWeXO+x0H+TqtDMwiNnQDlqtZg8C1M8+3hsvwJNDjaSb7jG+HZAO\n" +
			"UBFkcd78x+eZLpfBIwvVerXYP2gyS8a6Y4701tfW2w0DzMtmRA0Kj2YB9I+YU7Ed\n" +
			"jkkXMb8CAwEAAaNTMFEwHQYDVR0OBBYEFHGu4gshdD/pJO4fTXNfoSYhJL4hMB8G\n" +
			"A1UdIwQYMBaAFHGu4gshdD/pJO4fTXNfoSYhJL4hMA8GA1UdEwEB/wQFMAMBAf8w\n" +
			"DQYJKoZIhvcNAQELBQADggEBAFWpTj7oPwhYPW09vCQ7UXFt5lSzCIbXAf4GUUkE\n" +
			"ZIymbBVVyCSQhbBBVWvr6EHHt5KpI4Q7dKnNT0hw8+4QNz0TIXcd9IM/IE8TLaEl\n" +
			"eCn/GuFTFsWSeefb4fkUzlcAR9Qw7OeAorPJNRs8oRYXX1+8qOfhnYwQSYq0fUC3\n" +
			"EqiQDrqDLuBXeYar9oJckGNkzm9nxgdVjJiu9PmQWophvcTVIgfiJtUKcZn5724B\n" +
			"tA5wHufPOB5SYsEf5pAY26miJB9mZondsN7OxL9wxQ6d+b3WhMXXCd31unddpZaR\n" +
			"Mya42WGMkpOYZq7BXGf4VqyEv2f/y3ir3X2TKx33hRBtwAo=\n" +
			"</ds:X509Certificate>\n" +
			"                </ds:X509Data>\n" +
			"            </ds:KeyInfo>\n" +
			"        </md:KeyDescriptor>\n" +
			"        <md:KeyDescriptor use=\"encryption\">\n" +
			"            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
			"                <ds:X509Data>\n" +
			"                    <ds:X509Certificate>MIID3zCCAsegAwIBAgIUb0xgAHok8te7sBj3lXiOrXpLv9kwDQYJKoZIhvcNAQEL\n" +
			"BQAwfzELMAkGA1UEBhMCREsxEDAOBgNVBAgMB0Rlbm1hcmsxEzARBgNVBAcMCkNv\n" +
			"cGVuaGFnZW4xITAfBgNVBAoMGERpZ2l0YWxpc2VyaW5nc3N0eXJlbHNlbjEQMA4G\n" +
			"A1UECwwHT0lPU0FNTDEUMBIGA1UEAwwLT0lPU0FNTCBJRFAwHhcNMjAxMjI4MDk0\n" +
			"MjAzWhcNMzAxMjI2MDk0MjAzWjB/MQswCQYDVQQGEwJESzEQMA4GA1UECAwHRGVu\n" +
			"bWFyazETMBEGA1UEBwwKQ29wZW5oYWdlbjEhMB8GA1UECgwYRGlnaXRhbGlzZXJp\n" +
			"bmdzc3R5cmVsc2VuMRAwDgYDVQQLDAdPSU9TQU1MMRQwEgYDVQQDDAtPSU9TQU1M\n" +
			"IElEUDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO50DYKJnT1p6I7T\n" +
			"WQzWEnhGDOJSNtovch4yBsHgrt4G2FRkor5V4wbteyXpmZ8kTqcrGymwwewhHdSR\n" +
			"NP4GxLRPp0eBpPuCJfXp4zkpkNnnJ0FoxU5AQD9bMNmdM4bl/P8L7diPOIkaOK/+\n" +
			"cIZhC6QDwP4azskqI6iWm9QFREH/MBezeQEIpseM6/ARlJUdH0rlsxr/w33H7nBh\n" +
			"pEk1TE2PxBhSpWeXO+x0H+TqtDMwiNnQDlqtZg8C1M8+3hsvwJNDjaSb7jG+HZAO\n" +
			"UBFkcd78x+eZLpfBIwvVerXYP2gyS8a6Y4701tfW2w0DzMtmRA0Kj2YB9I+YU7Ed\n" +
			"jkkXMb8CAwEAAaNTMFEwHQYDVR0OBBYEFHGu4gshdD/pJO4fTXNfoSYhJL4hMB8G\n" +
			"A1UdIwQYMBaAFHGu4gshdD/pJO4fTXNfoSYhJL4hMA8GA1UdEwEB/wQFMAMBAf8w\n" +
			"DQYJKoZIhvcNAQELBQADggEBAFWpTj7oPwhYPW09vCQ7UXFt5lSzCIbXAf4GUUkE\n" +
			"ZIymbBVVyCSQhbBBVWvr6EHHt5KpI4Q7dKnNT0hw8+4QNz0TIXcd9IM/IE8TLaEl\n" +
			"eCn/GuFTFsWSeefb4fkUzlcAR9Qw7OeAorPJNRs8oRYXX1+8qOfhnYwQSYq0fUC3\n" +
			"EqiQDrqDLuBXeYar9oJckGNkzm9nxgdVjJiu9PmQWophvcTVIgfiJtUKcZn5724B\n" +
			"tA5wHufPOB5SYsEf5pAY26miJB9mZondsN7OxL9wxQ6d+b3WhMXXCd31unddpZaR\n" +
			"Mya42WGMkpOYZq7BXGf4VqyEv2f/y3ir3X2TKx33hRBtwAo=\n" +
			"</ds:X509Certificate>\n" +
			"                </ds:X509Data>\n" +
			"            </ds:KeyInfo>\n" +
			"        </md:KeyDescriptor>\n" +
			"        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8081/saml/logout\" ResponseLocation=\"http://localhost:8081/saml/logout/response\"/>\n" +
			"        <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8081/saml/login\"/>\n" +
			"    </md:IDPSSODescriptor>\n" +
			"</md:EntityDescriptor>";

	public static final String BAD_IDP_METADATA = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"077ae9ba-e94a-3ced-89a7-ddf7638bccf5\" entityID=\"http://notmockidp.localhost\">\n" +
			"    <md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
			"        <md:KeyDescriptor use=\"signing\">\n" +
			"            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
			"                <ds:X509Data>\n" +
			"                    <ds:X509Certificate>MIID3zCCAsegAwIBAgIUb0xgAHok8te7sBj3lXiOrXpLv9kwDQYJKoZIhvcNAQEL\n" +
			"BQAwfzELMAkGA1UEBhMCREsxEDAOBgNVBAgMB0Rlbm1hcmsxEzARBgNVBAcMCkNv\n" +
			"cGVuaGFnZW4xITAfBgNVBAoMGERpZ2l0YWxpc2VyaW5nc3N0eXJlbHNlbjEQMA4G\n" +
			"A1UECwwHT0lPU0FNTDEUMBIGA1UEAwwLT0lPU0FNTCBJRFAwHhcNMjAxMjI4MDk0\n" +
			"MjAzWhcNMzAxMjI2MDk0MjAzWjB/MQswCQYDVQQGEwJESzEQMA4GA1UECAwHRGVu\n" +
			"bWFyazETMBEGA1UEBwwKQ29wZW5oYWdlbjEhMB8GA1UECgwYRGlnaXRhbGlzZXJp\n" +
			"bmdzc3R5cmVsc2VuMRAwDgYDVQQLDAdPSU9TQU1MMRQwEgYDVQQDDAtPSU9TQU1M\n" +
			"IElEUDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO50DYKJnT1p6I7T\n" +
			"WQzWEnhGDOJSNtovch4yBsHgrt4G2FRkor5V4wbteyXpmZ8kTqcrGymwwewhHdSR\n" +
			"NP4GxLRPp0eBpPuCJfXp4zkpkNnnJ0FoxU5AQD9bMNmdM4bl/P8L7diPOIkaOK/+\n" +
			"cIZhC6QDwP4azskqI6iWm9QFREH/MBezeQEIpseM6/ARlJUdH0rlsxr/w33H7nBh\n" +
			"pEk1TE2PxBhSpWeXO+x0H+TqtDMwiNnQDlqtZg8C1M8+3hsvwJNDjaSb7jG+HZAO\n" +
			"UBFkcd78x+eZLpfBIwvVerXYP2gyS8a6Y4701tfW2w0DzMtmRA0Kj2YB9I+YU7Ed\n" +
			"jkkXMb8CAwEAAaNTMFEwHQYDVR0OBBYEFHGu4gshdD/pJO4fTXNfoSYhJL4hMB8G\n" +
			"A1UdIwQYMBaAFHGu4gshdD/pJO4fTXNfoSYhJL4hMA8GA1UdEwEB/wQFMAMBAf8w\n" +
			"DQYJKoZIhvcNAQELBQADggEBAFWpTj7oPwhYPW09vCQ7UXFt5lSzCIbXAf4GUUkE\n" +
			"ZIymbBVVyCSQhbBBVWvr6EHHt5KpI4Q7dKnNT0hw8+4QNz0TIXcd9IM/IE8TLaEl\n" +
			"eCn/GuFTFsWSeefb4fkUzlcAR9Qw7OeAorPJNRs8oRYXX1+8qOfhnYwQSYq0fUC3\n" +
			"EqiQDrqDLuBXeYar9oJckGNkzm9nxgdVjJiu9PmQWophvcTVIgfiJtUKcZn5724B\n" +
			"tA5wHufPOB5SYsEf5pAY26miJB9mZondsN7OxL9wxQ6d+b3WhMXXCd31unddpZaR\n" +
			"Mya42WGMkpOYZq7BXGf4VqyEv2f/y3ir3X2TKx33hRBtwAo=\n" +
			"</ds:X509Certificate>\n" +
			"                </ds:X509Data>\n" +
			"            </ds:KeyInfo>\n" +
			"        </md:KeyDescriptor>\n" +
			"        <md:KeyDescriptor use=\"encryption\">\n" +
			"            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
			"                <ds:X509Data>\n" +
			"                    <ds:X509Certificate>MIID3zCCAsegAwIBAgIUb0xgAHok8te7sBj3lXiOrXpLv9kwDQYJKoZIhvcNAQEL\n" +
			"BQAwfzELMAkGA1UEBhMCREsxEDAOBgNVBAgMB0Rlbm1hcmsxEzARBgNVBAcMCkNv\n" +
			"cGVuaGFnZW4xITAfBgNVBAoMGERpZ2l0YWxpc2VyaW5nc3N0eXJlbHNlbjEQMA4G\n" +
			"A1UECwwHT0lPU0FNTDEUMBIGA1UEAwwLT0lPU0FNTCBJRFAwHhcNMjAxMjI4MDk0\n" +
			"MjAzWhcNMzAxMjI2MDk0MjAzWjB/MQswCQYDVQQGEwJESzEQMA4GA1UECAwHRGVu\n" +
			"bWFyazETMBEGA1UEBwwKQ29wZW5oYWdlbjEhMB8GA1UECgwYRGlnaXRhbGlzZXJp\n" +
			"bmdzc3R5cmVsc2VuMRAwDgYDVQQLDAdPSU9TQU1MMRQwEgYDVQQDDAtPSU9TQU1M\n" +
			"IElEUDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO50DYKJnT1p6I7T\n" +
			"WQzWEnhGDOJSNtovch4yBsHgrt4G2FRkor5V4wbteyXpmZ8kTqcrGymwwewhHdSR\n" +
			"NP4GxLRPp0eBpPuCJfXp4zkpkNnnJ0FoxU5AQD9bMNmdM4bl/P8L7diPOIkaOK/+\n" +
			"cIZhC6QDwP4azskqI6iWm9QFREH/MBezeQEIpseM6/ARlJUdH0rlsxr/w33H7nBh\n" +
			"pEk1TE2PxBhSpWeXO+x0H+TqtDMwiNnQDlqtZg8C1M8+3hsvwJNDjaSb7jG+HZAO\n" +
			"UBFkcd78x+eZLpfBIwvVerXYP2gyS8a6Y4701tfW2w0DzMtmRA0Kj2YB9I+YU7Ed\n" +
			"jkkXMb8CAwEAAaNTMFEwHQYDVR0OBBYEFHGu4gshdD/pJO4fTXNfoSYhJL4hMB8G\n" +
			"A1UdIwQYMBaAFHGu4gshdD/pJO4fTXNfoSYhJL4hMA8GA1UdEwEB/wQFMAMBAf8w\n" +
			"DQYJKoZIhvcNAQELBQADggEBAFWpTj7oPwhYPW09vCQ7UXFt5lSzCIbXAf4GUUkE\n" +
			"ZIymbBVVyCSQhbBBVWvr6EHHt5KpI4Q7dKnNT0hw8+4QNz0TIXcd9IM/IE8TLaEl\n" +
			"eCn/GuFTFsWSeefb4fkUzlcAR9Qw7OeAorPJNRs8oRYXX1+8qOfhnYwQSYq0fUC3\n" +
			"EqiQDrqDLuBXeYar9oJckGNkzm9nxgdVjJiu9PmQWophvcTVIgfiJtUKcZn5724B\n" +
			"tA5wHufPOB5SYsEf5pAY26miJB9mZondsN7OxL9wxQ6d+b3WhMXXCd31unddpZaR\n" +
			"Mya42WGMkpOYZq7BXGf4VqyEv2f/y3ir3X2TKx33hRBtwAo=\n" +
			"</ds:X509Certificate>\n" +
			"                </ds:X509Data>\n" +
			"            </ds:KeyInfo>\n" +
			"        </md:KeyDescriptor>\n" +
			"        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8081/saml/logout\" ResponseLocation=\"http://localhost:8081/saml/logout/response\"/>\n" +
			"        <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8081/saml/login\"/>\n" +
			"    </md:IDPSSODescriptor>\n" +
			"</md:EntityDescriptor>";
	public static final String BAD_SP_ASSERTION_CONSUMER_URL = "http://localhost:8080/sso";
	
	public static final String VALID_CERTIFICATE = "MIIGJjCCBQ6gAwIBAgIEW607GjANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJE" + 
			"SzESMBAGA1UECgwJVFJVU1QyNDA4MSUwIwYDVQQDDBxUUlVTVDI0MDggU3lzdGVt" + 
			"dGVzdCBYWElJIENBMB4XDTE5MTIxNjE0MzE1NFoXDTIyMTIxNjE0MzEwN1owgZAx" + 
			"CzAJBgNVBAYTAkRLMScwJQYDVQQKDB5ORVRTIERBTklEIEEvUyAvLyBDVlI6MzA4" + 
			"MDg0NjAxWDAgBgNVBAUTGUNWUjozMDgwODQ2MC1GSUQ6OTQ3MzEzMTUwNAYDVQQD" + 
			"DC1UVSBHRU5FUkVMIEZPQ0VTIGd5bGRpZyAoZnVua3Rpb25zY2VydGlmaWthdCkw" + 
			"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1oIiZqfo6pai5XoKDBlrt" + 
			"sckoUrj2AxK9neEWWjB6HtzXeVou/AnA5R5xZL+3BpCoZHkoI9ncsh+dTNSeFgNk" + 
			"WkZXRIYK9RYAsxvpr3vTlvDtwfGxY9KLQJJrU/8N0EQbdfNncz6cDNBpoYQRv573" + 
			"nOZdwQKp3sAo+ONDw69ttghOlQekOpbeMwAjTwBRSEWPmqAbsCH+H5niU6TlUfWW" + 
			"J3WXLeQD4m7AOFEWpYDtTl2ZpN/sEoaAEvnwMZpT6aqbegipIB++llsR8Hc8pd/J" + 
			"nChfwOQrx1gBPn7oSfGLYQS4R1ZPlsredAkWiWGvWnxtJ46AUVNZEzydcIaHkyCv" + 
			"AgMBAAGjggLNMIICyTAOBgNVHQ8BAf8EBAMCA7gwgZcGCCsGAQUFBwEBBIGKMIGH" + 
			"MDwGCCsGAQUFBzABhjBodHRwOi8vb2NzcC5zeXN0ZW10ZXN0MjIudHJ1c3QyNDA4" + 
			"LmNvbS9yZXNwb25kZXIwRwYIKwYBBQUHMAKGO2h0dHA6Ly9mLmFpYS5zeXN0ZW10" + 
			"ZXN0MjIudHJ1c3QyNDA4LmNvbS9zeXN0ZW10ZXN0MjItY2EuY2VyMIIBIAYDVR0g" + 
			"BIIBFzCCARMwggEPBg0rBgEEAYH0UQIEBgQDMIH9MC8GCCsGAQUFBwIBFiNodHRw" + 
			"Oi8vd3d3LnRydXN0MjQwOC5jb20vcmVwb3NpdG9yeTCByQYIKwYBBQUHAgIwgbww" + 
			"DBYFRGFuSUQwAwIBARqBq0RhbklEIHRlc3QgY2VydGlmaWthdGVyIGZyYSBkZW5u" + 
			"ZSBDQSB1ZHN0ZWRlcyB1bmRlciBPSUQgMS4zLjYuMS40LjEuMzEzMTMuMi40LjYu" + 
			"NC4zLiBEYW5JRCB0ZXN0IGNlcnRpZmljYXRlcyBmcm9tIHRoaXMgQ0EgYXJlIGlz" + 
			"c3VlZCB1bmRlciBPSUQgMS4zLjYuMS40LjEuMzEzMTMuMi40LjYuNC4zLjCBrQYD" + 
			"VR0fBIGlMIGiMD2gO6A5hjdodHRwOi8vY3JsLnN5c3RlbXRlc3QyMi50cnVzdDI0" + 
			"MDguY29tL3N5c3RlbXRlc3QyMjEuY3JsMGGgX6BdpFswWTELMAkGA1UEBhMCREsx" + 
			"EjAQBgNVBAoMCVRSVVNUMjQwODElMCMGA1UEAwwcVFJVU1QyNDA4IFN5c3RlbXRl" + 
			"c3QgWFhJSSBDQTEPMA0GA1UEAwwGQ1JMMjE0MB8GA1UdIwQYMBaAFKuoAUQZsLND" + 
			"mdr6fMzSABgD5zy/MB0GA1UdDgQWBBQBeqJr/Y3aBTNh08u88qjEhB6GETAJBgNV" + 
			"HRMEAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQB7XyjSExCey9MOZxwR7RYjAfbOz/hL" + 
			"VNe1/Maw7Q7tLDVFwjmyZMbpxEAGlTFlo8y8yW5Dc6QQQejQ8+OCtbsJ2MmZfRf4" + 
			"HvezKIVwhZO2wUBbtUroiiatGiKE75GELjDkCI5iEo+aQFxzZ+saKWB6iyQkk9Lq" + 
			"Qs4+ut4HwUj2a3pXyXc7NfY+ivOxYYYOoPqvrhqEWTdjJv6A2mF6cdWKlZKBnvr8" + 
			"ndkVGQpHDHIUq9BcwGw6iVhaJcAoSl+i4kAjg3gNyWcr0UonyjwkQmaFMQJTkO95" + 
			"lDtn6XOLgXTwKS5X65cLhBDZqXPyNMaR+jGkQ6Ert5jceanwXzaKkLT5";

	public static final String REVOKED_CERTIFICATE = "MIIGKDCCBRCgAwIBAgIEW607HjANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJE" + 
			"SzESMBAGA1UECgwJVFJVU1QyNDA4MSUwIwYDVQQDDBxUUlVTVDI0MDggU3lzdGVt" + 
			"dGVzdCBYWElJIENBMB4XDTE5MTIxNjE0MzQxN1oXDTIyMTIxNjE0MzM0N1owgZIx" + 
			"CzAJBgNVBAYTAkRLMScwJQYDVQQKDB5ORVRTIERBTklEIEEvUyAvLyBDVlI6MzA4" + 
			"MDg0NjAxWjAgBgNVBAUTGUNWUjozMDgwODQ2MC1GSUQ6NDUzMjc0NzMwNgYDVQQD" + 
			"DC9UVSBHRU5FUkVMIEZPQ0VTIHNww6ZycmV0IChmdW5rdGlvbnNjZXJ0aWZpa2F0" + 
			"KTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJqKd1cVjcteIQ0jfcn2" + 
			"lmjZS3lNzqYAjCKs7MhPAB4P8FSpxzn4hW6azYK0Vsy8NGBTijuQYHI2zSCgpIBO" + 
			"C7DnuF1+JdpoqzPdSt967/3efmQe60JXKeyHViMJqCgB+vBmbvhAVl9v2qDWhj5H" + 
			"m2CSC7SvLCffuFITinO2ZTgTNjvEYqqRm6k/G8E7F4rpuRB25DdCkt8NlOUoT7aN" + 
			"+0lH/2UH9vyDaGCXreesLyAEbBOW+w5NxZFS88bvFGlIqg5CujInwbUjATRl2Wm8" + 
			"FnZ9WkbJ7VdceXHcNkz/QiLIYHZt0aGEz6cXvBc8zSSmV4D1shHLz376Uhm01873" + 
			"1X0CAwEAAaOCAs0wggLJMA4GA1UdDwEB/wQEAwIDuDCBlwYIKwYBBQUHAQEEgYow" + 
			"gYcwPAYIKwYBBQUHMAGGMGh0dHA6Ly9vY3NwLnN5c3RlbXRlc3QyMi50cnVzdDI0" + 
			"MDguY29tL3Jlc3BvbmRlcjBHBggrBgEFBQcwAoY7aHR0cDovL2YuYWlhLnN5c3Rl" + 
			"bXRlc3QyMi50cnVzdDI0MDguY29tL3N5c3RlbXRlc3QyMi1jYS5jZXIwggEgBgNV" + 
			"HSAEggEXMIIBEzCCAQ8GDSsGAQQBgfRRAgQGBAMwgf0wLwYIKwYBBQUHAgEWI2h0" + 
			"dHA6Ly93d3cudHJ1c3QyNDA4LmNvbS9yZXBvc2l0b3J5MIHJBggrBgEFBQcCAjCB" + 
			"vDAMFgVEYW5JRDADAgEBGoGrRGFuSUQgdGVzdCBjZXJ0aWZpa2F0ZXIgZnJhIGRl" + 
			"bm5lIENBIHVkc3RlZGVzIHVuZGVyIE9JRCAxLjMuNi4xLjQuMS4zMTMxMy4yLjQu" + 
			"Ni40LjMuIERhbklEIHRlc3QgY2VydGlmaWNhdGVzIGZyb20gdGhpcyBDQSBhcmUg" + 
			"aXNzdWVkIHVuZGVyIE9JRCAxLjMuNi4xLjQuMS4zMTMxMy4yLjQuNi40LjMuMIGt" + 
			"BgNVHR8EgaUwgaIwPaA7oDmGN2h0dHA6Ly9jcmwuc3lzdGVtdGVzdDIyLnRydXN0" + 
			"MjQwOC5jb20vc3lzdGVtdGVzdDIyMS5jcmwwYaBfoF2kWzBZMQswCQYDVQQGEwJE" + 
			"SzESMBAGA1UECgwJVFJVU1QyNDA4MSUwIwYDVQQDDBxUUlVTVDI0MDggU3lzdGVt" + 
			"dGVzdCBYWElJIENBMQ8wDQYDVQQDDAZDUkwyMTQwHwYDVR0jBBgwFoAUq6gBRBmw" + 
			"s0OZ2vp8zNIAGAPnPL8wHQYDVR0OBBYEFJddclhedsyHjXSrF7JG81IPRuz9MAkG" + 
			"A1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAJSf6/PJ4fGW4LYtgA/758n51KN0" + 
			"ccY+80Qk0Fc01/chDHSXCbyVkQm7/02dggnV/VWrnKy1IY5dSu5rJ45Aijg4zADZ" + 
			"/1eeeaSRvRiYz2+jIIPuGkMbHUdDJM6RuCertu/Pq2IQFIB0t/4EahVxTJcWmWY0" + 
			"j3TQWARCJfoE2baAD/xKasUNAItq9w8T6AhxFb1g2A4fUVhdKDIqA+SLNzc0VO9V" + 
			"xhvTIY8nNgEWuW8XKeUXPk/z4WNojNlO2NiHBJzyhEvptvIUvgshbLYD4vJZwry3" + 
			"9dk+tZf4c/vNlk57P2hcK4sPtqrxlKxrvZFeOA0Jn9PVbn0KWw/lOxx3w24="; 
}
