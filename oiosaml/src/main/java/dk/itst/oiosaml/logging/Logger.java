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
 * Kasper Vestergaard Møller <kvm@schultz.dk>
 */
package dk.itst.oiosaml.logging;

/**
 * This interface is used for doing logging in oiosaml.java. All methods must be thread safe.
 */
public interface Logger {
    public boolean isDebugEnabled();
    public void debug(Object message);
    public void debug(Object message, Throwable exception);
    public boolean isInfoEnabled();
    public void info(Object message);
    public void info(Object message, Throwable exception);
    public void warn(Object message);
    public void warn(Object message, Throwable exception);
    public void error(Object message);
    public void error(Object message, Throwable exception);

    /**
     * Initializes the logger with a name.
     */
    public void init(String name);
}
