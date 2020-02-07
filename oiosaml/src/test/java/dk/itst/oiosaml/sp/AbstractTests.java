package dk.itst.oiosaml.sp;

import org.jmock.Mockery;
import org.jmock.integration.junit4.JMock;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;

@RunWith(JMock.class)
public abstract class AbstractTests {
	protected Mockery context = new Mockery();

	@BeforeClass
	public static void configure() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}
}
