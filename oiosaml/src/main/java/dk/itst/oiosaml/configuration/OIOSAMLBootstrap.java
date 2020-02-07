package dk.itst.oiosaml.configuration;

import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;

import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;

public class OIOSAMLBootstrap {
	private static boolean bootstrapped = false;

	public static synchronized void init() {
		if (!bootstrapped) {
			bootstrapped = true;
			
			try {
				DefaultBootstrap.bootstrap();
			} catch (ConfigurationException e) {
				throw new WrappedException(Layer.DATAACCESS, e);
			}
		}
	}
}
