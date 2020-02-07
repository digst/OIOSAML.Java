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
package dk.itst.oiosaml.configuration;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.helper.DeveloperHelper;
import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;
import dk.itst.oiosaml.sp.service.SPFilter;
import dk.itst.oiosaml.sp.service.session.SameSiteSessionSynchronizer;
import dk.itst.oiosaml.sp.service.session.SessionCopyListener;
import dk.itst.oiosaml.sp.service.util.Constants;

/**
 * Utility class to obtain a handle to all property values within the current
 * project.
 *
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 * @author Aage Nielsen <ani@openminds.dk>
 * @author Carsten Larsen <cas@schultz.dk>
 *
 */
public class FileConfiguration implements SAMLConfiguration {
    private static final Logger log = LoggerFactory.getLogger(FileConfiguration.class);
    private String homeDir;
    private String configurationFileName;
    private Configuration systemConfiguration;
    private SameSiteSessionSynchronizer sameSiteSessionSynchronizer;

    /**
     * Tries to resolve {@link Constants#INIT_OIOSAML_FILE}, {@link Constants#INIT_OIOSAML_HOME} and {@link Constants#INIT_OIOSAML_NAME} from web.xml file.
     *
     */
    public FileConfiguration() {
        // Read in application name
        String applicationName = SystemConfiguration.getApplicationName();
        if(applicationName !=null)
            log.info(Constants.INIT_OIOSAML_NAME + " set to " + applicationName + " in web.xml");
        else
            log.info(Constants.INIT_OIOSAML_NAME + " was not defined in web.xml.");

        // Read in path to configuration library
        String homeParam = SystemConfiguration.getHomeDir();
        if(homeParam != null)
            log.info(Constants.INIT_OIOSAML_HOME + " set to " + homeParam + " in web.xml");
        else
            log.info(Constants.INIT_OIOSAML_HOME + " was not defined in web.xml.");

        // Read in name of configuration file
        String fullPathToConfigurationFile = SystemConfiguration.getFullPathToConfigurationFile();
        if(fullPathToConfigurationFile != null)
            log.info(Constants.INIT_OIOSAML_FILE + " set to " + fullPathToConfigurationFile + " in web.xml");
        else
            log.info(Constants.INIT_OIOSAML_FILE + " was not defined in web.xml.");

        Map<String, String> params = new HashMap<String, String>();
        if (fullPathToConfigurationFile != null) {
            params.put(Constants.INIT_OIOSAML_FILE, fullPathToConfigurationFile);
        } else {
            // Locate path to configuration folder if not set in web.xml
            if (homeParam == null) {
                homeParam = System.getProperty(SAMLUtil.OIOSAML_HOME);
                log.info(Constants.INIT_OIOSAML_HOME + " not set in web.xml. Setting it to " + SAMLUtil.OIOSAML_HOME + " Java system property with value: " + homeParam);
            }
            if (homeParam == null) {
                homeParam = System.getProperty("user.home") + File.separator + ".oiosaml";
                log.info(Constants.INIT_OIOSAML_HOME + " not set in Java system property. Setting it to default path: " + homeParam);
            }

            params.put(Constants.INIT_OIOSAML_HOME, homeParam);
            params.put(Constants.INIT_OIOSAML_NAME, applicationName);
        }

        setInitConfiguration(params);
    }
    
    /**
     * Get the current system configuration. The configuration is stored in
     * {@link SAMLUtil#OIOSAML_HOME}. The property is normally set in
     * {@link SPFilter}.
     *
     * @throws IllegalStateException
     *             When the system has not been configured properly yet.
     */
    public Configuration getSystemConfiguration() throws IllegalStateException {
        if (systemConfiguration != null) {
            return systemConfiguration;
        }
        
        if (homeDir == null || !isConfigured()) {
            throw new IllegalStateException("System not configured");
        }
        
        CompositeConfiguration conf = new CompositeConfiguration();
        conf.setProperty(SAMLUtil.OIOSAML_HOME, homeDir);

        try {
            conf.addConfiguration(new PropertiesConfiguration(new File(homeDir, configurationFileName)));
            conf.addConfiguration(getCommonConfiguration());

            systemConfiguration = conf;
            return systemConfiguration;
        } catch (ConfigurationException e) {
            log.error("Cannot load the configuration file", e);
            throw new WrappedException(Layer.DATAACCESS, e);
        } catch (IOException e) {
            log.error("Unable to load oiosaml-common.propeties from classpath", e);
            throw new WrappedException(Layer.DATAACCESS, e);
        }
    }
    
	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public SameSiteSessionSynchronizer getSameSiteSessionSynchronizer() {
		if (sameSiteSessionSynchronizer != null) {
			return sameSiteSessionSynchronizer;
		}

		try {
	        String handlerClass = getSystemConfiguration().getString(Constants.PROP_SAME_SITE_SESSION_SYNCHRONIZER, "dk.itst.oiosaml.sp.service.session.SessionCopyListener");

	        Class clazz = Class.forName(handlerClass);

	        return (SameSiteSessionSynchronizer) clazz.getDeclaredConstructor().newInstance();
		}
		catch (Exception ex) {
			log.error("Failed to initialize SameSiteSessionSynchronizer - defaulting to SessionCopyListener", ex);
		}
		
		return new SessionCopyListener();
	}

    public Configuration getCommonConfiguration() throws IOException {
        CompositeConfiguration conf = new CompositeConfiguration();
        Enumeration<URL> resources = SAMLConfiguration.class.getClassLoader().getResources("oiosaml-common.properties");
        while (resources.hasMoreElements()) {
            URL u = resources.nextElement();
            log.debug("Loading config from " + u);
            try {
                conf.addConfiguration(new PropertiesConfiguration(u));
            } catch (ConfigurationException e) {
                log.error("Cannot load the configuration file", e);
                throw new WrappedException(Layer.DATAACCESS, e);
            }
        }

        return conf;
    }

    public boolean isConfigured() {
        if (homeDir == null)
            return false;

        log.info("Config filename: " + homeDir + configurationFileName);
        File config = new File(homeDir + configurationFileName);

        log.info("Looking in : " + config.getAbsolutePath());
        return config.exists();
    }

    public KeyStore getKeystore() throws WrappedException {
        KeyStore keystore = null;

        File keystoreFile = new File(getSystemConfiguration().getString(
                Constants.PROP_CERTIFICATE_LOCATION));
        // If path is not absolute ... check if the path is relative to the home dir.
        if(!keystoreFile.exists()){
            keystoreFile = new File(homeDir + getSystemConfiguration().getString(
                    Constants.PROP_CERTIFICATE_LOCATION));
        }
        try {
            InputStream input = new FileInputStream(keystoreFile);
            input = new BufferedInputStream(input);
            input.mark(1024 * 1024);
            try {
                keystore = loadStore(input, getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD),
                        "PKCS12");
            } catch (IOException e) {
                log.debug("Keystore is not of type 'PCKS12' Trying type 'JKS'.");
                try {
                    input.reset();
                    keystore = loadStore(input,
                            getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD), "JKS");
                } catch (IOException ioe) {
					DeveloperHelper.log("It is not possible to access the configured keystore. Please check that the configured path and password are correct.");
					
                    log.error("Unable to find keystore file. Looking for: " + keystoreFile.getAbsolutePath());
                    throw new WrappedException(Layer.DATAACCESS, ioe);
                } catch (Exception ec) {
                    log.error("Exception occured while processing keystore: " + keystoreFile.getAbsolutePath());
                    throw new WrappedException(Layer.DATAACCESS, ec);
                }
            } catch (Exception ex) {
                log.error("Exception occured while processing keystore: " + keystoreFile.getAbsolutePath());
                throw new WrappedException(Layer.DATAACCESS, ex);
            }

        } catch (FileNotFoundException e) {
            log.error("Unable to find keystore file. Looking for: " + keystoreFile.getAbsolutePath());
            throw new WrappedException(Layer.DATAACCESS, e);
        }
        return keystore;
    }


    private static KeyStore loadStore(InputStream input, String password, String type) throws KeyStoreException,NoSuchAlgorithmException, CertificateException, IOException {
        KeyStore ks = KeyStore.getInstance(type);
        char[] jksPassword = password.toCharArray();
        ks.load(input, jksPassword);
        input.close();
        return ks;
    }

    public XMLObject getSPMetaData() throws WrappedException {
        String filename = getSystemConfiguration().getString(Constants.SP_METADATA_FILE);
        String directory = homeDir + getSystemConfiguration().getString(Constants.SP_METADATA_DIRECTORY);
        String spMetadataFileName = directory + "/" + filename;

        XMLObject unmarshallElementFromFile = null;
        try {
            unmarshallElementFromFile = SAMLUtil.unmarshallElementFromFile(spMetadataFileName);
        } catch (Exception e) {
            log.error("Unable to find SP metadata file. Tries to look for: " + spMetadataFileName);
            throw new WrappedException(Layer.DATAACCESS, e);
        }
        return unmarshallElementFromFile;
    }

    public List<XMLObject> getListOfIdpMetadata() throws WrappedException {
        List<XMLObject> descriptors = new ArrayList<XMLObject>();
        String protocol = getSystemConfiguration().getString(Constants.PROP_PROTOCOL);
        if (getSystemConfiguration().getString(Constants.IDP_METADATA_FILE) != null) {
            String idpFileName = homeDir + getSystemConfiguration().getString(Constants.IDP_METADATA_DIRECTORY) + "/"
                    + getSystemConfiguration().getString(Constants.IDP_METADATA_FILE);
            File md = new File(idpFileName);
            log.info("Loading " + protocol + " metadata from " + md);
            try {
                XMLObject descriptor = SAMLUtil.unmarshallElementFromFile(md.getAbsolutePath());
                if (descriptor instanceof EntityDescriptor) {
                    descriptors.add(descriptor);
                } else if (descriptor instanceof EntitiesDescriptor) {
                    EntitiesDescriptor desc = (EntitiesDescriptor) descriptor;
                    descriptors.addAll(desc.getEntityDescriptors());
                } else {
                    throw new RuntimeException("Metadata file " + md + " does not contain an EntityDescriptor. Found "
                            + descriptor.getElementQName() + ", expected " + EntityDescriptor.ELEMENT_QNAME);
                }
            } catch (RuntimeException e) {
                log.error("Unable to load metadata from " + md
                        + ". File must contain valid XML and have EntityDescriptor as top tag", e);
                throw e;
            }
        } else {
            String directory = homeDir + getSystemConfiguration().getString(Constants.IDP_METADATA_DIRECTORY);
            File idpDir = new File(directory);
            File[] files = idpDir.listFiles(new FilenameFilter() {
                public boolean accept(File dir, String name) {
                    return name.toLowerCase().endsWith(".xml");
                }
            });
            if (files != null) {
                for (File md : files) {
                    log.info("Loading " + protocol + " metadata from " + md);
                    try {
                        XMLObject descriptor = SAMLUtil.unmarshallElementFromFile(md.getAbsolutePath());
                        if (descriptor instanceof EntityDescriptor) {
                            descriptors.add(descriptor);
                        } else if (descriptor instanceof EntitiesDescriptor) {
                            EntitiesDescriptor desc = (EntitiesDescriptor) descriptor;
                            descriptors.addAll(desc.getEntityDescriptors());
                        } else {
                            throw new RuntimeException("Metadata file " + md
                                    + " does not contain an EntityDescriptor. Found " + descriptor.getElementQName()
                                    + ", expected " + EntityDescriptor.ELEMENT_QNAME);
                        }
                    } catch (RuntimeException e) {
                        log.error("Unable to load metadata from " + md
                                + ". File must contain valid XML and have EntityDescriptor as top tag", e);
                        throw e;
                    }
                }
            }
        }
        if (descriptors.isEmpty()) {
            throw new IllegalStateException("No IdP descriptors found in ! At least one file is required.");
        }
        return descriptors;
    }

    /**
     * This method ONLY exists to support unit and integration tests. Do not use it for other purposes.
     * Either {@link Constants#INIT_OIOSAML_FILE} or {@link Constants#INIT_OIOSAML_HOME} must be specified. If both is specified then {@link Constants#INIT_OIOSAML_FILE} takes precedense
     * if {@link Constants#INIT_OIOSAML_HOME} is specified then {@link Constants#INIT_OIOSAML_NAME} is optionally and {@link SAMLUtil#OIOSAML_DEFAULT_CONFIGURATION_FILE} is used as default name for the configuration file.
     * If either {@link Constants#INIT_OIOSAML_FILE} or {@link Constants#INIT_OIOSAML_HOME} is not set then the system is set to be not configured.
     */
    public void setInitConfiguration(Map<String, String> params) {
        systemConfiguration = null;
        if (params != null) {
            if (params.containsKey(Constants.INIT_OIOSAML_FILE)) {
                String configurationFile = params.get(Constants.INIT_OIOSAML_FILE);
                if (configurationFile != null) {
                    int lastPathSeperatorIndex = configurationFile.lastIndexOf(File.separator) + 1;
                    configurationFileName = configurationFile.substring((lastPathSeperatorIndex), configurationFile.length());
                    homeDir = configurationFile.substring(0, lastPathSeperatorIndex);
                }
            } else if (params.containsKey(Constants.INIT_OIOSAML_HOME)) {
                String pathToConfigurationFolder = params.get(Constants.INIT_OIOSAML_HOME);
                if (pathToConfigurationFolder != null) {
                    homeDir = pathToConfigurationFolder;
                    configurationFileName = SAMLUtil.OIOSAML_DEFAULT_CONFIGURATION_FILE;
                }

                // Apply application name if configured
                String applicationName = params.get(Constants.INIT_OIOSAML_NAME);
                if(applicationName != null && !applicationName.trim().isEmpty()){
                    // First remove ending file separator if present
                    if (homeDir.endsWith(File.separator))
                        homeDir = homeDir.substring(0, homeDir.length() - 1);
                    homeDir += "-" + applicationName;
                }

                // Add ending file separator to home dir if not present.
                if (!homeDir.endsWith(File.separator))
                    homeDir = homeDir + File.separator;
            }
            else{
                homeDir = null;
                configurationFileName = null;
            }

            // Write configurations to the log
            log.info("Path to configuration folder set to: " + homeDir);
            log.info("Configuration file name set to: " + configurationFileName);
        }
    }

    public void setConfiguration(Configuration configuration) {
        systemConfiguration = configuration;
    }

    public String getHomeDir() {
        return homeDir;
    }
}
