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

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.service.util.Constants;
import org.apache.commons.configuration.Configuration;
import org.apache.log4j.LogManager;
import org.apache.log4j.xml.DOMConfigurator;

import java.io.*;

/**
 * This class supports logging using the log4j logger.
 */
public class Log4JLogger implements Logger {
    private static boolean initialized = false;
    private static boolean initializationOngoing = false;
    private static Object lock = new Object();

    private org.apache.log4j.Logger log;

    @Override
    public boolean isDebugEnabled() {
        return log.isDebugEnabled();
    }

    @Override
    public void debug(Object message) {
        log.debug(message);
    }

    @Override
    public void debug(Object message, Throwable exception) {
        log.debug(message, exception);
    }

    @Override
    public boolean isInfoEnabled() {
        return log.isInfoEnabled();
    }

    @Override
    public void info(Object message) {
        log.info(message);
    }

    @Override
    public void info(Object message, Throwable exception) {
        log.info(message, exception);
    }

    @Override
    public void warn(Object message) {
        log.warn(message);
    }

    @Override
    public void warn(Object message, Throwable exception) {
        log.warn(message, exception);
    }

    @Override
    public void error(Object message) {
        log.error(message);
    }

    @Override
    public void error(Object message, Throwable exception) {
        log.error(message, exception);
    }

    public void init(String name) {
        log = org.apache.log4j.Logger.getLogger(name); // Logger is initialized first so that log statements can be written in this method. Log4j is always initialized with a default logger that logs to the console.

        synchronized (lock) {
            if (!initialized && !initializationOngoing) {
                // initializationOngoing is necessary in order for not the same thread to reenter the synchronized block recursively
                initializationOngoing = true;

                Configuration systemConfiguration;
                try{
                    systemConfiguration = SAMLConfigurationFactory.getConfiguration().getSystemConfiguration();
                }
                // This should only happen during execution of unit tests where the logging framework cannot be initialized because the oiosaml configuration is not available.
                catch (IllegalStateException e){
                    error("Unable to retrieve configuration", e);
                    initializationOngoing = false;
                    initialized = true; // no reason for others to try to initialize.
                    return;
                }

                String homeDir = systemConfiguration.getString(SAMLUtil.OIOSAML_HOME);
                String logFileName = homeDir + systemConfiguration.getString(Constants.PROP_LOG_FILE_NAME);

                String modified;
                StringBuilder contents = new StringBuilder();

                try {
                    BufferedReader input = new BufferedReader(new FileReader(logFileName));

                    int val;
                    while ((val = input.read()) != -1) {
                        contents.append((char) val);
                    }

                    input.close();

                    if (homeDir.endsWith(File.separator)) {
                        homeDir = homeDir.substring(0, homeDir.length() - 1); // Remove separator if exist
                    }
                    modified = contents.toString().replaceAll("\\$\\{" + SAMLUtil.OIOSAML_HOME + "\\}", homeDir.replace("\\", "/")); // separator must be '/' in log4j configuration file.

                } catch (FileNotFoundException e) {
                    log.error("Unable to find log file. Tries to look for: " + logFileName);
                    throw new WrappedException(Layer.DATAACCESS, e);
                } catch (IOException e) {
                    log.error("Unable to process log file.");
                    throw new WrappedException(Layer.DATAACCESS, e);
                }

                ByteArrayInputStream log4jStream = new ByteArrayInputStream(modified.getBytes());

                try {
                    new DOMConfigurator().doConfigure(log4jStream, LogManager.getLoggerRepository());
                } finally {
                    if (log4jStream != null)
                        try {
                            log4jStream.close();
                        } catch (IOException e) {
                            throw new WrappedException(Layer.UNDEFINED, e);
                        }
                }

                initializationOngoing = false;
                initialized = true;
            }
        }
    }
}
