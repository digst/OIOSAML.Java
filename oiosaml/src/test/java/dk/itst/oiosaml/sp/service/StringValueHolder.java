package dk.itst.oiosaml.sp.service;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

public class StringValueHolder extends BaseMatcher<String> {
	private String value;
	public boolean matches(Object item) {
		value = (String) item;
		return true;
	}

	public void describeTo(Description description) {}
	
	public String getValue() {
		return value;
	}
	
	public void setValue(String value) {
		this.value = value;
	}
}

