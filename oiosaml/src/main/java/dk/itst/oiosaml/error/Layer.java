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
package dk.itst.oiosaml.error;

/**
 * Feasible layers to use when throwing unrecoverable exceptions
 * 
 * @author lsteinth
 */
public class Layer {

	public static final String VERSION = "$Id: Layer.java 2829 2008-05-13 12:11:31Z jre $";
	public static final Layer CLIENT = new Layer("CLIENT");
	public static final Layer BUSINESS = new Layer("BUSINESS");
	public static final Layer DATAACCESS = new Layer("RESOURCE");
	public static final Layer UNDEFINED = new Layer("UNDEFINED");

	private String value;

	/**
	 * Create a new layer
	 * 
	 * @param value
	 *            The value of the layer
	 */
	private Layer(String value) {
		this.value = value;
	}

	/**
	 * 
	 * @return The value of the layer
	 */
	public String getValue() {
		return value;
	}

	/**
	 * {@inheritDoc Object#toString()}
	 */
	public String toString() {
		return value;
	}

	/**
	 * @see Object#equals(Object)
	 */
	public boolean equals(Layer layer) {
		return value.equals(layer.value);
	}

	/**
	 * {@inheritDoc Object#hashCode()}
	 */
	public int hashCode() {
		return getValue().hashCode();
	}

	/**
	 * {@inheritDoc Object#equals(Object)}
	 */
	public boolean equals(Object obj) {
		if (!(obj instanceof Layer)) {
			return false;
		}

		return ((getValue() != null) && (getValue().equals(((Layer) obj).getValue())));
	}
}
