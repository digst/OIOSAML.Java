/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2009 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.service.session;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;

import java.util.Timer;
import java.util.TimerTask;

public class SessionCleaner {
	private static final Logger log = LoggerFactory.getLogger(SessionCleaner.class);
	
	private static Timer cleanupTimer = null;

	public static void startCleaner(final SessionHandler handler, int maxInactiveIntervalSeconds, int delay) {
		log.info("Starting session cleaner");
		
		if (cleanupTimer != null) {
			cleanupTimer.cancel();
		}
		
		cleanupTimer = new Timer("Session Cleanup");
		final long sessionCleanupDelay = (long)maxInactiveIntervalSeconds * 1000;
		final long requestIdsCleanupDelay = delay * 1000L;		
		
		cleanupTimer.schedule(new TimerTask() {
			public void run() {
				log.debug("Cleaning sessions older than " + sessionCleanupDelay + " and request ids older than " + requestIdsCleanupDelay);
				
				handler.cleanup(requestIdsCleanupDelay, sessionCleanupDelay);
			}
		}, sessionCleanupDelay, sessionCleanupDelay);
	}
	
	public static void stopCleaner() {
		if (cleanupTimer != null) {
			cleanupTimer.cancel();
			cleanupTimer = null;
		}
	}
	
}
