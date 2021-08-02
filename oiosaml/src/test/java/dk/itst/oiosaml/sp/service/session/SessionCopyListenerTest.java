package dk.itst.oiosaml.sp.service.session;

import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import org.junit.Test;

import javax.servlet.http.HttpSessionEvent;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertNotNull;

public class SessionCopyListenerTest extends AbstractServiceTests {

	protected SessionCopyListener cut;

	@Test //NLRFIM-126: without synchronized on linkSession() this test fails
	public void testDeadlock() throws InterruptedException {
		cut = new SessionCopyListener();

		List<CopyListenerTestThread> threads = new ArrayList<CopyListenerTestThread>();

		for(int i = 0; i < 10000; i++) {
			threads.add(new CopyListenerTestThread(""+i));
		}

		for (CopyListenerTestThread t: threads) {
			t.start();
		}

		for (CopyListenerTestThread t: threads) {
			t.join();
		}

		for (CopyListenerTestThread t: threads) {
			assertNotNull(""+t.id, cut.getSession("req"+t.id));
		}
	}

	class CopyListenerTestThread extends Thread {
		private String id;

		public CopyListenerTestThread(String id) {
			this.id = id;
		}

		public void run() {
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			cut.sessionCreated(new HttpSessionEvent(session));
			cut.linkSession("req"+id, session.getId());
		}
	}

}
