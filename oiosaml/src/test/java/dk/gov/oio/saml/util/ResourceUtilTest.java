package dk.gov.oio.saml.util;

import org.junit.jupiter.api.*;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

class ResourceUtilTest {

    private static Path externalPath;

    @BeforeAll
    static void beforeAll() throws IOException {
        externalPath = Files.createTempFile("ResourceUtil", "test");
        try (BufferedWriter writer = Files.newBufferedWriter(externalPath, StandardCharsets.UTF_8)) {
            writer.write("this.is.a.test=1234");
        }
    }

    @DisplayName("Test GetResourceAsFile from external file")
    @Test
    void testGetResourceAsFileFromExternalFile() throws InternalException {
        File file = ResourceUtil.getResourceAsFile(externalPath.toString());
        Assertions.assertTrue(file.isFile() && file.canRead());
    }

    @DisplayName("Test GetResourceAsFile from classpath")
    @Test
    void testGetResourceAsFileFromClassPath() throws InternalException {
        File file = ResourceUtil.getResourceAsFile("resource.config.test");
        Assertions.assertTrue(file.isFile() && file.canRead());
    }

    @DisplayName("Test GetResourceAsFile from jar")
    @Test
    void testGetResourceAsFileFromJar() throws InternalException {
        File file = ResourceUtil.getResourceAsFile("LICENSE-junit.txt");
        Assertions.assertTrue(file.isFile() && file.canRead());
    }

    @DisplayName("Test GetResourceAsFile handles non-file (WildFly vfs:) URLs - issue #80")
    @Test
    void testToFileFromVfsUrl() throws Exception {
        // Simulate an application-server VFS resource URL (e.g. WildFly 'vfs:') backed by a
        // real file. Such URLs are not 'file:' URLs, so the old new File(url.toURI()) approach
        // throws; toFile must instead copy the resource to a readable temp file.
        URLStreamHandler vfsHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL u) {
                return new URLConnection(u) {
                    @Override public void connect() { }
                    @Override public InputStream getInputStream() throws IOException {
                        return Files.newInputStream(externalPath);
                    }
                };
            }
        };
        URL vfsUrl = new URL(null, "vfs:/content/app.war/WEB-INF/classes/oiosaml.properties", vfsHandler);

        // The naive conversion that caused issue #80 fails for such URLs...
        Assertions.assertThrows(IllegalArgumentException.class, () -> new File(vfsUrl.toURI()));

        // ...while toFile resolves it to a readable file holding the original content.
        File file = ResourceUtil.toFile(vfsUrl, "oiosaml.properties");
        Assertions.assertTrue(file.isFile() && file.canRead());
        Assertions.assertEquals("this.is.a.test=1234",
                new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
    }

    @DisplayName("Test GetResourceAsStream from classpath")
    @Test
    void testGetResourceAsStreamFromClassPath() throws IOException, InternalException {
        try (InputStream inputStream = ResourceUtil.getResourceAsStream("resource.config.test")) {
            Assertions.assertNotNull(inputStream.read());
        }
    }

    @DisplayName("Test GetResourceAsStream from file")
    @Test
    void testGetResourceAsStreamFromFile() throws IOException, InternalException {
        try (InputStream inputStream = ResourceUtil.getResourceAsStream(externalPath.toString())) {
            // Empty file will return -1 (EOF)
            Assertions.assertNotNull(inputStream.read());
        }
    }

    @DisplayName("Test GetConfig from file")
    @Test
    void testGetConfigFromExternalFile() throws IOException {
        Map map = ResourceUtil.getConfig(externalPath.toString());
        Assertions.assertEquals("1234", map.get("this.is.a.test"));
    }

    @DisplayName("Test GetConfig from classpath")
    @Test
    void testGetConfigFromClassPath() {
        Map map = ResourceUtil.getConfig("resource.config.test");
        Assertions.assertEquals("123456", map.get("this.is.a.read.test"));
    }
}