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
 * created by Trifork A/S are Copyright (C) 2009 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.model;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;

import dk.itst.oiosaml.helper.DeveloperHelper;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import dk.itst.oiosaml.sp.model.validation.ValidationException;

public class OIOEncryptedAssertion {
	private static final Logger log = LoggerFactory.getLogger(OIOEncryptedAssertion.class);
	
	private final EncryptedAssertion encrypted;

	public OIOEncryptedAssertion(EncryptedAssertion assertion) {
		this.encrypted = assertion;
		if (assertion.getEncryptedData().getType() == null) {
			assertion.getEncryptedData().setType("http://www.w3.org/2001/04/xmlenc#Element");
		}
	}

	public OIOAssertion decryptAssertion(Credential credential) {
		KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(credential);
		
		ChainingEncryptedKeyResolver kekResolver = new ChainingEncryptedKeyResolver();
		kekResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
		kekResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
		kekResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());
		
		try {
			if (log.isDebugEnabled()) {
				log.debug("Assertion encrypted: " + encrypted);
			}

			Decrypter decrypter = new Decrypter(null, keyResolver, kekResolver);
			decrypter.setRootInNewDocument(true);

			Assertion assertion = decrypter.decrypt(encrypted);

			if (log.isDebugEnabled()) {
				OIOAssertion res = new OIOAssertion(assertion);
				log.debug("Decrypted assertion: " + res.toXML());
			}

			return new OIOAssertion(assertion);
		} catch (DecryptionException e) {
			DeveloperHelper.log("Unable to decrypt assertion - this might be caused by using Oracle Java without installing the \"Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files\".");
			throw new ValidationException(e);
		}
	}

}
