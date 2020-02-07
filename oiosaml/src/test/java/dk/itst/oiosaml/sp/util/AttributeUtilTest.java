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
package dk.itst.oiosaml.sp.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.schema.impl.XSAnyUnmarshaller;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.AbstractTests;


public class AttributeUtilTest extends AbstractTests {

	@Test
	public void testExtractAttributeValue() {
		Attribute attr = AttributeUtil.createAttribute("test", "test", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT);
		attr.getAttributeValues().add(AttributeUtil.createAttributeValue("value"));
		
		assertEquals("value", AttributeUtil.extractAttributeValueValue(attr));
	}
	
	@Test
	public void testExtractComplexAttributeValue() throws Exception {
		Attribute attr = AttributeUtil.createAttribute("test", "test", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT);
		XSAnyBuilder builder = new XSAnyBuilder();
		XSAny ep = builder.buildObject(SAMLConstants.SAML20_NS, AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);

		String xml = "<t:test xmlns:t=\"http://test.org\"><t:more>text here</t:more></t:test>";
		XMLObject val = new XSAnyUnmarshaller().unmarshall(SAMLUtil.loadElementFromString(xml));
		ep.getUnknownXMLObjects().add(val);
		attr.getAttributeValues().add(ep);
		
		assertNotNull(AttributeUtil.extractAttributeValueValue(attr));
		assertTrue(AttributeUtil.extractAttributeValueValue(attr).endsWith(xml));
	}
	
	@Test
	public void testExtractAttributeValues() {
		final String VALUE1 = "value1";
		final String VALUE2 = "value2";
		
		Attribute attr = AttributeUtil.createAttribute("test", "test", OIOSAMLConstants.URI_ATTRIBUTE_NAME_FORMAT);
		attr.getAttributeValues().add(AttributeUtil.createAttributeValue(VALUE1));
		attr.getAttributeValues().add(AttributeUtil.createAttributeValue(VALUE2));
		
		boolean found1 = false;
		boolean found2 = false;
		List<String> values = AttributeUtil.extractAttributeValueValues(attr);
		for (String str : values) {
			if(VALUE1.equals(str)) {
				found1 = true;
			} else if(VALUE2.equals(str)) {
				found2 = true;
			}
		}
		assertTrue(VALUE1, found1);
		assertTrue(VALUE2, found2);
	}
	
}
