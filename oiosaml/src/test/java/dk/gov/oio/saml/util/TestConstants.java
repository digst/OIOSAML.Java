package dk.gov.oio.saml.util;

public class TestConstants {
    public static final String SP_ENTITY_ID = "http://sp.localhost";
    public static final String SP_BASE_URL = "http://localhost:8080";
    public static final String SP_ROUTING_BASE = "saml";
    public static final String SP_ROUTING_ERROR = "error";
    public static final String SP_ROUTING_METADATA = "metadata";
    public static final String SP_ROUTING_LOGOUT = "logout";
    public static final String SP_ROUTING_LOGOUT_RESPONSE = "logoutResponse";
    public static final String SP_ROUTING_ASSERTION = "assertionConsumer";
    public static final String SP_ASSERTION_CONSUMER_URL = "http://localhost:8080/saml/assertionConsumer";
    public static final String SP_LOGOUT_REQUEST_URL = "http://localhost:8080/saml/logout";
    public static final String SP_LOGOUT_RESPONSE_URL = "http://localhost:8080/saml/logout/response";
    public static final String SP_KEYSTORE_LOCATION = "sp.pfx";
    public static final String SP_KEYSTORE_ALIAS = "1";
    public static final String SP_KEYSTORE_PASSWORD = "Test1234";

    public static final String IDP_ENTITY_ID = "http://mockidp.localhost";
    public static final String IDP_METADATA_URL = "http://localhost:8081/saml/metadata";
    public static final String IDP_LOGOUT_REQUEST_URL = "http://localhost:8081/saml/logout";
    public static final String IDP_LOGOUT_RESPONSE_URL = "http://localhost:8081/saml/logout/response";

    public static final String IDP_METADATA = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_077ae9ba-e94a-3ced-89a7-ddf7638bccf5\" entityID=\"http://mockidp.localhost\">\n" +
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

    public static final String BAD_IDP_METADATA = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_077ae9ba-e94a-3ced-89a7-ddf7638bccf5\" entityID=\"http://notmockidp.localhost\">\n" +
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
    
    public static final String VALID_CERTIFICATE = "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";

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
