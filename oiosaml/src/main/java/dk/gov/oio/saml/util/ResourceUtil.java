package dk.gov.oio.saml.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class ResourceUtil {
    private static final Logger log = LoggerFactory.getLogger(ResourceUtil.class);

    /**
     * Returns a file for reading the specified resource.
     * @param resourceName Resource name from classpath or absolute path to resource
     * @return file pointing to resource
     * @throws InternalException if resource is missing
     */
    public static File getResourceAsFile(String resourceName) throws InternalException {
        if (StringUtil.isEmpty(resourceName)) {
            throw new InternalException(String.format("Unable to load resource file '%s'", resourceName));
        }
        try {
            File file;
            URL url = ResourceUtil.getClassLoader().getResource(resourceName);
            if (url != null) {
                file = new File(url.toURI());
            } else {
                file = new File(resourceName);
            }

            if (!file.exists()) {
                throw new InternalException(String.format("Unable to load resource file '%s'", resourceName));
            }

            return file;

        } catch (URISyntaxException e) {
            throw new InternalException(String.format("Unable to load resource file '%s'", resourceName), e);
        }
    }

    /**
     * Returns an input stream for reading the specified resource.
     * @param resourceName Resource name from classpath or absolute path to resource
     * @return resource as stream
     * @throws InternalException if resource is missing
     */
    public static InputStream getResourceAsStream(String resourceName) throws InternalException {
        if (StringUtil.isEmpty(resourceName)) {
            throw new InternalException(String.format("Unable to load resource '%s'", resourceName));
        }
        // Try to load resource from classpath to support JAR retrieval
        InputStream inputStream = getClassLoader().getResourceAsStream(resourceName);

        if (null == inputStream) {
            try {
                // Try to load from file to support external resources
                return new FileInputStream(getResourceAsFile(resourceName));
            } catch (FileNotFoundException e) {
                throw new InternalException(String.format("Unable to load resource '%s'", resourceName), e);
            }
        }
        return inputStream;
    }

    /**
     * Get configuration from resource
     * @param configurationFile
     * @return Map containing properties from the configuration file map is empty if unable to load file
     */
    public static Map<String, String> getConfig(String configurationFile) {
        HashMap<String, String> configMap = new HashMap<>();
        if (StringUtil.isNotEmpty(configurationFile)) {
            try (InputStream is = ResourceUtil.getResourceAsStream(configurationFile)) {
                Properties p = new Properties();
                p.load(is);

                @SuppressWarnings("unchecked")
                Enumeration<String> enums = (Enumeration<String>) p.propertyNames();
                while (enums.hasMoreElements()) {
                    String key = enums.nextElement();
                    String value = p.getProperty(key);

                    configMap.put(key,  value);
                }
            }
            catch (Exception ex) {
                log.error("Failed to load external configuration file: '{}'", configurationFile, ex);
            }
        }
        return configMap;
    }

    private static ClassLoader getClassLoader() {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = Class.class.getClassLoader();
        }
        return classLoader;
    }
}
