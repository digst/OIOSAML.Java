package dk.itst.oiosaml.helper;

import java.util.ArrayList;
import java.util.List;

import dk.itst.oiosaml.logging.Logger;
import dk.itst.oiosaml.logging.LoggerFactory;

public class DeveloperHelper {
	private static final Logger log = LoggerFactory.getLogger(DeveloperHelper.class);
	
	public static void log(String message) {
		List<String> messageLines = convertToLines(message);
		StringBuilder builder = new StringBuilder();
		
		builder.append("\n\n *****************************************************************************\n");
		builder.append(" *   DEVELOPER HINT   - the message below might explain the error            *\n");
		builder.append(" *****************************************************************************\n");
		
		for (String messageLine : messageLines) {
			builder.append(" * " + messageLine + " *\n");
		}

		builder.append(" *****************************************************************************\n\n");
		
		log.info(builder.toString());
	}
	
	private static List<String> convertToLines(String message) {
		List<String> messageLines = new ArrayList<String>();

		while (true) {
			if (message.length() <= 73) {
				StringBuilder messageLine = new StringBuilder(message);
				while (messageLine.length() < 73) {
					messageLine.append(" ");
				}

				messageLines.add(messageLine.toString());
				break;
			}
			
			// scan for first space
			int cutPoint = 73;
			for ( ; cutPoint >= 0; cutPoint--) {
				if (message.charAt(cutPoint) == ' ') {
					break;
				}
			}
			
			if (cutPoint == 0) {
				cutPoint = 73;
			}
			
			StringBuilder messageLine = new StringBuilder(message.substring(0, cutPoint));
			while (messageLine.length() < 73) {
				messageLine.append(" ");
			}

			messageLines.add(messageLine.toString());
			
			// skip spaces on next line
			while (message.length() > cutPoint && message.charAt(cutPoint) == ' ') {
				cutPoint++;
			}

			message = message.substring(cutPoint);
		}
		
		return messageLines;
	}
}
