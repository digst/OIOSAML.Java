package dk.gov.oio.saml.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
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

            if (url != null && "jar".equals(url.getProtocol())) {
                // To access resources as files inside a jar we need to copy them to disk (use when unable to access as stream)
                try (InputStream inputStream = ResourceUtil.getResourceAsStream(resourceName)) {
                    Path path = Files.createTempFile(resourceName, "tmp");
                    java.nio.file.Files.copy(inputStream, path, StandardCopyOption.REPLACE_EXISTING);
                    file = path.toFile();
                }
            } else if (url != null) {
                file = new File(url.toURI());
            } else {
                file = new File(resourceName);
            }

            if (!file.exists()) {
                throw new InternalException(String.format("Unable to load resource file '%s'", resourceName));
            }

            return file;

        } catch (URISyntaxException | IOException e) {
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
     * @param configurationFile name and location of configuration file
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
                log.warn("Failed to load external configuration file: '{}'", configurationFile, ex);
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
