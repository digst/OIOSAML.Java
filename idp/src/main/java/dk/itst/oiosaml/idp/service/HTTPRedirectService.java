package dk.itst.oiosaml.idp.service;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
public class HTTPRedirectService {

    public MessageContext<SAMLObject> getMessageContext(HttpServletRequest request) {
        MessageContext<SAMLObject> msgContext = null;

        try {
            HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
            decoder.setHttpServletRequest(request);

            BasicParserPool parserPool = new BasicParserPool();
            parserPool.initialize();

            decoder.setParserPool(parserPool);
            decoder.initialize();
            decoder.decode();

            msgContext = decoder.getMessageContext();

            decoder.destroy();
        } catch (MessageDecodingException | ComponentInitializationException e) {
            e.printStackTrace();
        }
        return msgContext;
    }
}
