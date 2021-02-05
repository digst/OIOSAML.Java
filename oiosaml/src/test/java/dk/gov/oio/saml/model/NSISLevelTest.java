package dk.gov.oio.saml.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class NSISLevelTest {
    @DisplayName("Test unknown input for getNSISLevelFromUrl")
    @Test
    public void testDefaultIsReturnedForUnknownInputWhenUrl() {
        Assertions.assertEquals(NSISLevel.HIGH, NSISLevel.getNSISLevelFromUrl("unknown", NSISLevel.HIGH));
    }

    @DisplayName("Test null input for getNSISLevelFromUrl")
    @Test
    public void testDefaultIsReturnedForNullInputWhenUrl() {
        Assertions.assertEquals(NSISLevel.HIGH, NSISLevel.getNSISLevelFromUrl(null, NSISLevel.HIGH));
    }

    @DisplayName("Test unknown input for getNSISLevelFromAttributeValue")
    @Test
    public void testDefaultIsReturnedForUnknownInputWhenAttributeValue() {
        Assertions.assertEquals(NSISLevel.HIGH, NSISLevel.getNSISLevelFromUrl("unknown", NSISLevel.HIGH));
    }

    @DisplayName("Test null input for getNSISLevelFromAttributeValue")
    @Test
    public void testDefaultIsReturnedForNullInputWhenAttributeValue() {
        Assertions.assertEquals(NSISLevel.HIGH, NSISLevel.getNSISLevelFromAttributeValue(null, NSISLevel.HIGH));
    }

    @DisplayName("Test can parse URL")
    @ParameterizedTest
    @MethodSource("provideUrlsForTestCanParseUrl")
    public void testCanParseUrl(String url, NSISLevel expectedLevel) {
        Assertions.assertEquals(expectedLevel, NSISLevel.getNSISLevelFromUrl(url, null));
    }

    @DisplayName("Test can parse attribute value")
    @ParameterizedTest
    @MethodSource("provideUrlsForTestCanParseAttributeValue")
    public void testCanParseAttributeValue(String attributeValue, NSISLevel expectedLevel) {
        Assertions.assertEquals(expectedLevel, NSISLevel.getNSISLevelFromAttributeValue(attributeValue, null));
    }

    private static Stream<Arguments> provideUrlsForTestCanParseUrl() {
        return Stream.of(
            Arguments.of("https://data.gov.dk/concept/core/nsis/loa/Low", NSISLevel.LOW),
            Arguments.of("https://data.gov.dk/concept/core/nsis/loa/Substantial", NSISLevel.SUBSTANTIAL),
            Arguments.of("https://data.gov.dk/concept/core/nsis/loa/High", NSISLevel.HIGH)
        );
    }

    private static Stream<Arguments> provideUrlsForTestCanParseAttributeValue() {
        return Stream.of(
                Arguments.of("Low", NSISLevel.LOW),
                Arguments.of("Substantial", NSISLevel.SUBSTANTIAL),
                Arguments.of("High", NSISLevel.HIGH)
        );
    }
}
