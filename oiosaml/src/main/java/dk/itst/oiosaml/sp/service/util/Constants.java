/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *   Aage Nielsen <ani@openminds.dk>
 *   Carsten Larsen <cas@schultz.dk>
 *
 */
package dk.itst.oiosaml.sp.service.util;

import org.opensaml.xml.signature.Signature;

import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.service.session.SessionHandler;

/**
 * Basic constants used within the library.
 * 
 */
public interface Constants {
	
	/**
	 * Session attribute for holding the user's current assertion. The value of the
	 * attribute should be a {@link UserAssertion}.
	 */
	static final String SESSION_USER_ASSERTION = "dk.itst.oiosaml.userassertion";

    // Constants used within query strings
    static final String QUERY_STRING_FORCE_AUTHN = "forceAuthn"; // Enables force authentication when querying IdP.

	// URI in the reference implementation
	static final String PROP_HOME = "oiosaml-sp.uri.home";
	static final String PROP_CERTIFICATE_LOCATION = "oiosaml-sp.certificate.location";
	static final String PROP_CERTIFICATE_PASSWORD = "oiosaml-sp.certificate.password";
	static final String PROP_IGNORE_CERTPATH = "oiosaml-sp.resolve.ignorecert";
	static final String PROP_RESOLVE_USERNAME = "oiosaml-sp.resolve.username";
	static final String PROP_RESOLVE_PASSWORD = "oiosaml-sp.resolve.password";
	static final String PROP_ASSURANCE_LEVEL = "oiosaml-sp.assurancelevel";
	static final String PROP_NSIS_LEVEL = "oiosaml-sp.nsislevel";
	static final String PROP_AUTHNCONTEXTCLASSREF_REQUEST = "oiosaml-sp.enable.authncontextclassref.request";
	static final String PROP_HTTP_PROXY_HOST = "oiosaml-sp.http.proxy.host";
	static final String PROP_HTTP_PROXY_PORT = "oiosaml-sp.http.proxy.port";

    // OCSP and CRL related configuration settings
    static final String PROP_CIRCUIT_BREAKER_ATTEMPTS_BEFORE_OPENING = "oiosaml-sp.cb.attempts.before.opening";
    static final String PROP_CIRCUIT_BREAKER_ATTEMPTS_WITHIN_IN_SECONDS = "oiosaml-sp.cb.attempts.within.in.seconds";
    static final String PROP_CIRCUIT_BREAKER_RESET_TIME_IN_SECONDS = "oiosaml-sp.cb.reset.time.in.seconds";
    static final String PROP_CIRCUIT_BREAKER_DELAY_BETWEEN_ATTEMPTS_IN_SECONDS = "oiosaml-sp.cb.delay.between.attempts.in.seconds";
    static final String PROP_CERTIFICATES_REMAIN_VALID_PERIOD_IN_SECONDS = "oiosaml-sp.remain.valid.period.in.seconds";
    static final String PROP_CRL = "oiosaml-sp.crl.";
	static final String PROP_CRL_CHECK_PERIOD = "oiosaml-sp.crl.period";
	static final String PROP_CRL_TRUSTSTORE = "oiosaml-sp.crl.truststore";
	static final String PROP_CRL_TRUSTSTORE_PASSWORD = "oiosaml-sp.crl.truststore.password";
	static final String PROP_OCSP_CA = "oiosaml-sp.ocsp.ca";
	static final String PROP_OCSP_RESPONDER = "oiosaml-sp.ocsp.responder";


    static final String PROP_REQUIRE_ENCRYPTION = "oiosaml-sp.encryption.force";
	static final String PROP_NUM_TRACKED_ASSERTIONIDS = "common.saml2.loggedinhandler.numusedassertionids";
	static final String PROP_VALIDATOR = "oiosaml-sp.assertion.validator";
	
	static final String PROP_NAMEID_POLICY = "oiosaml-sp.nameid.policy";
	static final String PROP_NAMEID_POLICY_ALLOW_CREATE = "oiosaml-sp.nameid.allowcreate";
	
	static final String PROP_ERROR_SERVLET = "oiosaml-sp.errors";
	
	/**
	 * Property pointing to a class which implements {@link SessionHandler}.
	 */
	static final String PROP_SESSION_HANDLER_FACTORY = "oiosaml-sp.sessionhandler.factory";
	
	/**
	 * Property indicating if IsPassive should be set to true or false.
	 */
	static final String PROP_PASSIVE = "oiosaml-sp.passive";
	
	/**
	 * Property for setting the username used for the anonymous user. The anonymous user is used when
	 * IsPassive is true, and the user is not signed in at the IdP.
	 */
	static final String PROP_PASSIVE_USER_ID = "oiosaml-sp.passive.user";
	
	/**
	 * A comma separated list of urls for which ForceAuthn should be set to true. 
	 * Each url is treated as a regular expression against the request (without the servlet path).
	 */
	static final String PROP_FORCE_AUTHN_URLS = "oiosaml-sp.authn.force";

	/**
	 * Path to the saml dispatcher servlet.
	 */
	static final String PROP_SAML_SERVLET = "oiosaml-sp.servlet";
	
	static final String PROP_AUTHENTICATION_HANDLER = "oiosaml-sp.authenticationhandler";
	
	static final String PROP_SUPPORTED_BINDINGS = "oiosaml-sp.bindings";
	
	/**
	 * Path to a servlet handling re-posts after authentication.
	 */
	static final String PROP_REPOST_SERVLET = "oiosaml-sp.repost";

	// Known SAML services
	static final String SERVICE_AUTHN_REQUEST = "<AuthnRequest>";
	static final String SERVICE_LOGOUT_REQUEST = "<LogoutRequest>";
	static final String SERVICE_LOGOUT_RESPONSE = "<LogoutResponse>";
	static final String SERVICE_ARTIFACT_RESOLVE = "<ArtifactResolve>";

	/**
	 * Standard request parameter for holding relay state.
	 */
	static final String SAML_RELAYSTATE = "RelayState";
	
	/**
	 * Standard request parameter for holding a saml request.
	 */
	static final String SAML_SAMLREQUEST = "SAMLRequest";
	
	/**
	 * Standard request parameter for holding a saml response.
	 */
	static final String SAML_SAMLRESPONSE = "SAMLResponse";
	
	/**
	 * Standard request parameter for holding a saml signature algorithm uri.
	 */
	static final String SAML_SIGALG = "SigAlg";
	
	/**
	 * Standard request parameter for holding a saml signature.
	 */
	static final String SAML_SIGNATURE = Signature.DEFAULT_ELEMENT_LOCAL_NAME;
	
	/**
	 * Standard request parameter for holding a saml artifact.
	 */
	static final String SAML_SAMLART = "SAMLart";

	static final String SHA1_WITH_RSA = "SHA1withRSA";
	
	static final String INIT_OIOSAML_HOME = "oiosaml-j.home";
	
	static final String INIT_OIOSAML_NAME = "oiosaml-j.name";

	static final String INIT_OIOSAML_FILE = "oiosaml-j.file";

	/**
	 * Configuration parameter pointing to the URL for the discovery service.
	 */
	static final String DISCOVERY_LOCATION = "oiosaml-sp.discovery";
	
	/**
	 * Configuration parameter containing the default IdP entity id if no _saml_idp cookie was set.
	 */
	static final String PROP_DISCOVERY_DEFAULT_IDP = "oiosaml-sp.discovery.default";

	/**
	 * Configuration parameter enabling IdP prompting if no IdP was discovered. Cannot be used in conjunction with {@link #PROP_DISCOVERY_DEFAULT_IDP}.
	 */
	static final String PROP_DISCOVERY_PROMPT = "oiosaml-sp.discovery.prompt";
	
	/**
	 * Custom servlet to use when prompting user for IdP.
	 */
	static final String PROP_DISCOVERY_PROMPT_SERVLET = "oiosaml-sp.discovery.prompt.servlet";
	
	/**
	 * Session and url parameter holding the current saml idp discovery value.
	 */
	static final String DISCOVERY_ATTRIBUTE = "_saml_idp";
		
	
	static final String PROP_LOG_FILE_NAME = "oiosaml-sp.log";

	/**
	 * ID of the protocol to use for SSO.
	 */
	static final String PROP_PROTOCOL = "oiosaml-sp.protocol";
	
	static final String ATTRIBUTE_ERROR = "error";
	static final String ATTRIBUTE_EXCEPTION = "exception";


	/**
	 * Property controlling if the service is running in developer mode. 
	 */
	static final String PROP_DEVEL_MODE = "oiosaml-sp.develmode";
	
	/**
	 * Property controlling if the service will show errormessages/stacktraces to the user
	 * NOTE! Should always be false in production, to void security issues with XML Encryption
	 */
	static final String PROP_SHOW_ERROR = "oiosaml-sp.showerror";

	/*
	 * Properties used when using filereferences to SP data files
	 * 
	 * */
	static final String SP_METADATA_FILE = "common.saml2.metadata.sp.filename";
	static final String SP_METADATA_DIRECTORY = "common.saml2.metadata.sp.directory";

	static final String IDP_METADATA_FILE = "common.saml2.metadata.idp.filename";
	static final String IDP_METADATA_DIRECTORY = "common.saml2.metadata.idp.directory";

	static final String SIGNATURE_ALGORITHM = "oiosaml-sp.signature.algorithm";
	
	/**
	 * Support for self-signed certificates. enabled = true, disabled = false.
	 * Default value is false.
	 */
	static final String SELF_SIGNED_CERT_SUPPORT = "oiosaml-sp.selfsignedcertificates";

	/**
	 * Disable revocation check on OCES-test certificates. Default is true
	 */
	static final String DISABLE_OCES_TEST_CRL_CHECK_BAD_SPELLING = "oiosaml-cp.crl.disable-in-oces-test";
	static final String DISABLE_OCES_TEST_CRL_CHECK = "oiosaml-sp.crl.disable-in-oces-test";
	
	/**
	 * Enable eid compatibility - note that this effects how AuthnRequests are generated
	 */
	static final String PROP_EID_COMPATIBLE = "oiosaml-sp.eid.compatible";

	/**
	 * Set this value to modify the clockskew (default is 5 minutes)
	 */
	static final String PROP_CLOCK_SKEW = "oiosaml-sp.clock.skew";
	
	/**
	 * Set this value to implement a custom SameSiteSessionSynchronizer
	 */
	static final String PROP_SAME_SITE_SESSION_SYNCHRONIZER = "oiosaml-sp.samesite.handler";

	/**
	 * Set this value to either "Person" or "Professional" to request those specific EID profiles
	 */
	static final String PROP_REQUESTED_PROFILE = "oiosaml-sp.requested.profile";
}
