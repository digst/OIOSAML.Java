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
 *
 */
package dk.itst.oiosaml.sp.model;

import java.security.PublicKey;

import javax.xml.crypto.dsig.XMLSignature;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import org.opensaml.Configuration;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ElementExtensibleXMLObject;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;

/**
 * Base class for all SAML objects.
 * 
 * This class defines default behavior, such as signature handling and serialization.
 * 
 * @author Joakim Recht <jre@trifork.com>
 *
 */
public class OIOSamlObject {
	private static final Logger log = LoggerFactory.getLogger(OIOSamlObject.class);

	private final XMLObject obj;

	public OIOSamlObject(XMLObject obj) {
		if (obj == null) throw new IllegalArgumentException("Object cannot be null");

		this.obj = obj;
	}
	
	@Override
	public String toString() {
		return "Object: " + obj;
	}
	
	/**
	 * Get an XML representation of the object.
	 */
	public String toXML() {
		Element e = SAMLUtil.marshallObject(obj);
		return XMLHelper.nodeToString(e);
	}

	/**
	 * Sign the saml object. 
	 * 
	 * The effect of calling this method is that a new Signature element is created, and the object is marshalled. 
	 * If {@link #toXML()} is called, the XML will contain a valid signature.
	 * 
	 * @param signingCredential The credential used for signing the object.
	 */
	@SuppressWarnings("deprecation")
	public void sign(Credential signingCredential) {
		Signature signature = SAMLUtil.buildXMLObject(Signature.class);
		if (!(obj instanceof SignableSAMLObject)) {
			throw new IllegalStateException("Object of type " + obj.getClass() + " is not signable");
		}
		// manually add the ds namespace, as it will be added to the inclusiveNamespaces element
		obj.addNamespace(new Namespace(XMLSignature.XMLNS, "ds"));
	
	    signature.setSigningCredential(signingCredential);
	    try {
	        SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null);
	    } catch (SecurityException e) {
	    	throw new WrappedException(Layer.BUSINESS, e);
	    }
	    
	    ((SignableSAMLObject)obj).setSignature(signature);
	
	    try {
	        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(obj);
	        if (marshaller == null) {
	            throw new RuntimeException("No marshaller registered for "
	                    + obj.getElementQName() + ", unable to marshall in preperation for signing");
	        }
	        marshaller.marshall(obj);
	
	        Signer.signObject(signature);
	    } catch (MarshallingException e) {
	        log.error("Unable to marshall protocol message in preparation for signing", e);
	    	throw new WrappedException(Layer.BUSINESS, e);
	    } catch (SignatureException e) {
	        log.error("Unable to sign protocol message", e);
	    	throw new WrappedException(Layer.BUSINESS, e);
	    }
	}

	/**
	 * Encode the SAML object to a base64 encoded string.
	 * 
	 * @return The XML representation encoded with base64. 
	 */
	public String toBase64() {
		Element element = SAMLUtil.marshallObject(obj);
		String xml = XMLHelper.nodeToString(element);
		return Base64.encodeBytes(xml.getBytes(), Base64.DONT_BREAK_LINES);
	}
	
	
	/**
	 * Check if the object has a signature.
	 */
	public boolean hasSignature() {
		if (!(obj instanceof SignableSAMLObject)) return false;
		return ((SignableSAMLObject)obj).getSignature() != null;
	}

	/**
	 * Check that a given object has been signed correctly with a specific {@link PublicKey}.
	 * 
	 * @return true, if the signableObject has been signed correctly with the given key.
	 * 	Returns <code>false</code> if the object is not signed at all.
	 */
	public boolean verifySignature(PublicKey publicKey) {
		if (publicKey == null) {
			throw new IllegalArgumentException("Certificate cannot be null");
		}
		Signature signature = null;
		if (obj instanceof SignableSAMLObject) {
			SignableSAMLObject signableObject = (SignableSAMLObject) obj;
			
			signature = signableObject.getSignature();
		} else if (obj instanceof ElementExtensibleXMLObject){
			signature = SAMLUtil.getFirstElement((ElementExtensibleXMLObject)obj, Signature.class);
		}
		
		if (signature == null) {
			log.warn("No signature present in object " + obj);
			return false;
		}
		
		// verify signature element according to SAML profile
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		try {
			profileValidator.validate(signature);
		}
		catch (Exception e) {
			log.warn("The signature does not meet the requirements indicated by the SAML profile of the XML signature", e);
			return false;
		}

		// verify signature
		BasicX509Credential credential = new BasicX509Credential();
		credential.setPublicKey(publicKey);
		SignatureValidator validator = new SignatureValidator(credential);
		try {
			validator.validate(signature);
			return true;
		} catch (ValidationException e) {
			log.warn("The signature does not match the signature of the login site", e);
			return false;
		}
	}

	public String toSoapEnvelope() {
		Body body = SAMLUtil.buildXMLObject(Body.class);
		body.getUnknownXMLObjects().add(obj);

		// Build output...
		Envelope envelope = SAMLUtil.buildXMLObject(Envelope.class);
		envelope.setBody(body);
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(envelope);
		try {
			Element e = marshaller.marshall(envelope);
			return XMLHelper.nodeToString(e);
		} catch (MarshallingException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}

	}

}
