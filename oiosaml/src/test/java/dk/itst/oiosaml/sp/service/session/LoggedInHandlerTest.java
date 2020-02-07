package dk.itst.oiosaml.sp.service.session;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.jmock.Expectations;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.util.Constants;

public class LoggedInHandlerTest extends AbstractServiceTests{
	
	
	@Before @After
	public void stopCleanup() {
		SessionCleaner.stopCleaner();
	}
	
	
	@Test
	public void testSetAssertion() {
		handler.setAssertion(session.getId(), new OIOAssertion(assertion));
		
		OIOAssertion assertion = handler.getAssertion(session.getId());
		assertEquals(this.assertion, assertion.getAssertion());
		
		String idx = new OIOAssertion(this.assertion).getSessionIndex();
		
		assertEquals(session.getId(), handler.getRelatedSessionId(idx));
		
	}

	@Test(expected=IllegalArgumentException.class)
	public void failOnReplayAssertionId() {
		context.checking(new Expectations() {{
			allowing(session).setAttribute(with(equal(Constants.SESSION_USER_ASSERTION)), with(any(UserAssertion.class)));
		}});
		handler.setAssertion(session.getId(), new OIOAssertion(assertion));
		
		// this is replay - should throw IllegalArgumentException
		handler.setAssertion(session.getId(), new OIOAssertion(assertion));
		
	}
	
	@Test
	public void testIsLoggedIn() {
		assertFalse(handler.isLoggedIn(session.getId()));
		setHandler();
		assertTrue(handler.isLoggedIn(session.getId()));
	}

	@Test
	public void testLogOut() {
		// session does not exist, no errors
		context.checking(new Expectations() {{ 
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		handler.logOut(session);
		context.assertIsSatisfied();
		
		setHandler();
		assertNotNull(handler.getAssertion(session.getId()));
		context.checking(new Expectations() {{ 
			one(session).removeAttribute(Constants.SESSION_USER_ASSERTION);
		}});
		handler.logOut(session);
		assertNull(handler.getAssertion(session.getId()));
	}

	@Test 
	public void cleanUpIsScheduled() throws Exception {
		SessionCleaner.startCleaner(handler, 1, 1);
		
		setHandler();
		assertTrue(handler.isLoggedIn(session.getId()));
		Thread.sleep(2100);
		assertFalse(handler.isLoggedIn(session.getId()));
	}
	
	@Test
	public void testStopSchedule() throws Exception {
		SessionCleaner.startCleaner(handler, 1, 1);
		SessionCleaner.stopCleaner();
		
		setHandler();
		assertTrue(handler.isLoggedIn(session.getId()));
		Thread.sleep(2100);
		assertTrue(handler.isLoggedIn(session.getId()));
	}

	@Test(expected=IllegalArgumentException.class)
	public void cleanupRequestIds() throws Exception {
		handler.registerRequest("1", "id");
		SessionCleaner.startCleaner(handler, 1, 1);
		
		Thread.sleep(2000);
		handler.removeEntityIdForRequest("1");
	}
	

}
