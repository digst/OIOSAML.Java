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

import java.util.Iterator;
import java.util.ServiceLoader;

public class LoggerFactory {
    private static final Logger log = LoggerFactory.getLogger(LoggerFactory.class);

    public static Logger getLogger(String name){
        Logger logger = null;
        ServiceLoader<Logger> configurationImplementations = ServiceLoader.load(Logger.class);
        for (Iterator<Logger> iterator = configurationImplementations.iterator(); iterator.hasNext();) {
            logger = iterator.next();
            if (iterator.hasNext()) {
// not really possible to log something at this point, as we do not have an instance of the Logger class yet!
//                log.error("Appears to be more than one logger implementation. Please check META-INF/services for occurencies. Choosing the implementation: " + logger.getClass().getName());
                break;
            }
        }
        logger.init(name);
        return logger;
    }

    public static Logger getLogger(Class<?> clazz){
        return getLogger(clazz.getCanonicalName());
    }
}
