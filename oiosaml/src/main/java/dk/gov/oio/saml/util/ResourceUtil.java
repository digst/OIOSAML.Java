package dk.gov.oio.saml.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
            URL url = ResourceUtil.getClassLoader().getResource(resourceName);
            File file = toFile(url, resourceName);

            if (!file.exists()) {
                throw new InternalException(String.format("Unable to load resource file '%s'", resourceName));
            }

            return file;

        } catch (URISyntaxException | IOException e) {
            throw new InternalException(String.format("Unable to load resource file '%s'", resourceName), e);
        }
    }

    /**
     * Resolve a classpath resource URL to a {@link File}.
     * <p>
     * A plain {@code file:} URL is used directly. Resources that are not backed by a real
     * filesystem file - inside a jar ({@code jar:}), or served by an application server
     * virtual file system such as WildFly/JBoss ({@code vfs:}, {@code vfszip:}) - cannot be
     * turned into a File with {@code new File(url.toURI())} (that throws
     * {@code IllegalArgumentException: URI scheme is not "file"}), so they are copied to a
     * temporary file through their stream instead. See issue #80.
     *
     * @param url URL returned by the classloader, or {@code null} when the resource is not on the classpath
     * @param resourceName original resource name, used as the absolute/external path fallback when {@code url} is null
     * @return file pointing to the resource
     */
    static File toFile(URL url, String resourceName) throws URISyntaxException, IOException {
        if (url != null && "file".equals(url.getProtocol())) {
            return new File(url.toURI());
        }

        if (url != null) {
            // Not a plain file (jar:, vfs:, vfszip:, ...) - copy to disk so it can be read as a File.
            // Use only the last path segment as the temp-file prefix: a resourceName that refers to a
            // file in a subdirectory (e.g. "config/oiosaml.properties") contains '/', which
            // createTempFile rejects with IllegalArgumentException. The "oiosaml-" prefix also
            // guarantees the minimum 3-character length required for the prefix.
            try (InputStream inputStream = url.openStream()) {
                String baseName = Paths.get(resourceName).getFileName().toString();
                Path path = Files.createTempFile("oiosaml-" + baseName, ".tmp");
                Files.copy(inputStream, path, StandardCopyOption.REPLACE_EXISTING);
                return path.toFile();
            }
        }

        return new File(resourceName);
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
