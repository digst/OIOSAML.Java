package dk.gov.oio.saml.model;

import dk.gov.oio.saml.extensions.appswitch.AppSwitchPlatform;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class AppSwitchPlatformEnumTest {
    @DisplayName("Test unknown input for getAppSwitchPlatform")
    @Test
    public void testIsReturnedForUnknownInputWhenUrl() {
        Assertions.assertEquals(NSISLevel.HIGH, NSISLevel.getNSISLevelFromUrl("unknown", NSISLevel.HIGH));
    }

    @DisplayName("Test can parse appswitch platform value")
    @ParameterizedTest
    @MethodSource("provideTestDataForAppSwitchPlatformEnum")
    public void testCanParseValue(String value, AppSwitchPlatform expected) {
        Assertions.assertEquals(expected, AppSwitchPlatform.getPlatformOrNull(value));
    }

    private static Stream<Arguments> provideTestDataForAppSwitchPlatformEnum() {
        return Stream.of(
            Arguments.of("Android", AppSwitchPlatform.Android),
                Arguments.of("android", AppSwitchPlatform.Android),
                Arguments.of("aNdRoId", AppSwitchPlatform.Android),
                Arguments.of("iOS", AppSwitchPlatform.iOS),
                Arguments.of("iOS", AppSwitchPlatform.iOS),
                Arguments.of("ios", AppSwitchPlatform.iOS),
                Arguments.of("UnknownPlatform", null),
                Arguments.of("    ", null),
                Arguments.of("", null),
                Arguments.of(null, null)

        );
    }
}
