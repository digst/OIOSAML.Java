package dk.gov.oio.saml.session;

public class AssertionWrapperHolder {
	private static ThreadLocal<AssertionWrapper> holder = new ThreadLocal<>();
	
	public static AssertionWrapper get() {
		return holder.get();
	}
	
	public static void set(AssertionWrapper wrapper) {
		holder.set(wrapper);
	}
	
	public static void clear() {
		holder.remove();
	}
}
