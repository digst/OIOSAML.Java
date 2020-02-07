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

import javax.xml.namespace.QName;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;

import dk.itst.oiosaml.common.OIOSAMLConstants;

/**
 * Class containing the assurance level associated with the login.
 * The currently known assurance levels are:
 * 2 - PASSWORD_ASSURANCE_LEVEL
 * 3 - CERTIFICATE_ASSURANCE_LEVEL
 * @author lsteinth
 *
 */
public class AssuranceLevel implements BRSSAMLExtensionObject {
	public static final String VERSION = "$Id: AssuranceLevel.java 2829 2008-05-13 12:11:31Z jre $";
    /** Element local name. */
    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "AssuranceLevel";

    /** Default element name. */
    public static final QName DEFAULT_ELEMENT_NAME = new QName(OIOSAMLConstants.BRS_NS, DEFAULT_ELEMENT_LOCAL_NAME, OIOSAMLConstants.BRS_PREFIX);

    public static final int PASSWORD_ASSURANCE_LEVEL = 2;
    public static final int CERTIFICATE_ASSURANCE_LEVEL = 3;
    public static final int DEFAULT_ASSURANCE_LEVEL = PASSWORD_ASSURANCE_LEVEL;
    
	private int value;
	/**
	 * Create a new assurance level with a given value
	 * @param value The value
	 */
	public AssuranceLevel(String value) {
		try {
			this.value = Integer.parseInt(value);
		} catch (NumberFormatException e) {
			this.value = DEFAULT_ASSURANCE_LEVEL;
		}
	}

	/**
	 * 
	 * @return The value associated with the assurance level
	 */
	public int getValue() {
		return value;
	}

	/**
	 * Set the value associated with the assurance level
	 * @param value The value
	 */
	public void setValue(int value) {
		this.value = value;
	}

	/**
	 * @see BRSSAMLExtensionObject#getXMLObject()
	 */
	public XMLObject getXMLObject() {
		XSAnyBuilder builder = new XSAnyBuilder();
		XSAny ep = builder.buildObject(OIOSAMLConstants.BRS_NS, DEFAULT_ELEMENT_LOCAL_NAME, OIOSAMLConstants.BRS_PREFIX);
		ep.setTextContent(String.valueOf(value));
		return ep;
	}
}
