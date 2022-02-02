package dk.gov.oio.saml.util;

import org.junit.jupiter.api.*;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
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