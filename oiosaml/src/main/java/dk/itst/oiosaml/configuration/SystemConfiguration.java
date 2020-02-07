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
 *   Kasper Vestergaard Møller <kvm@schultz.dk>
 *
 */
package dk.itst.oiosaml.configuration;

import dk.itst.oiosaml.sp.service.util.Constants;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * Utility class to obtain configuration settings from web.xml file
 * project.
 * 
 * @author Kasper Vestergaard Møller <kvm@schultz.dk>
 * 
 */
public class SystemConfiguration{

    /**
     * Returns home dir as set in web.xml
     * @return path to home dir or null if not defined
     */
    public static String getHomeDir(){
        // Read in path to configuration library
        try {
            Context env = (Context)new InitialContext().lookup("java:comp/env");
            return (String)env.lookup(Constants.INIT_OIOSAML_HOME);
        } catch (NamingException e) {
            return null;
        }
    }

    /**
     * Returns application name as set in web.xml
     * @return application name or null if not defined.
     */
    public static String getApplicationName(){
        // Read in path to configuration library
        try {
            Context env = (Context)new InitialContext().lookup("java:comp/env");
            return (String)env.lookup(Constants.INIT_OIOSAML_NAME);
        } catch (NamingException e) {
            return null;
        }
    }

    /**
     * Returns full path to configuration file as set in web.xml
     * @return full path to configuration file or null if not defined
     */
    public static String getFullPathToConfigurationFile(){
        // Read in path to configuration library
        try {
            Context env = (Context)new InitialContext().lookup("java:comp/env");
            return (String)env.lookup(Constants.INIT_OIOSAML_FILE);
        } catch (NamingException e) {
            return null;
        }
    }
}