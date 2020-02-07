package dk.itst.oiosaml.sp.model.validation;

import org.apache.commons.configuration.Configuration;
import org.joda.time.DateTime;

import dk.itst.oiosaml.configuration.SAMLConfigurationFactory;
import dk.itst.oiosaml.sp.service.util.Constants;

public class ClockSkewValidator {
	private static int clockSkew;

	static {
		Configuration configuration = SAMLConfigurationFactory.getConfiguration().getSystemConfiguration();
		clockSkew = configuration.getInt(Constants.PROP_CLOCK_SKEW, 5);
	}

	public static boolean isBeforeNow(DateTime dateTime) {
		DateTime dateTimePlusSkew = dateTime.minusMinutes(clockSkew);

		return dateTimePlusSkew.isBeforeNow();
	}
	
	public static boolean isAfterNow(DateTime dateTime) {
		DateTime dateTimeMinusSkew = dateTime.minusMinutes(-1 * clockSkew);
		
		return dateTimeMinusSkew.isAfterNow();
	}
}
