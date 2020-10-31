package net.luminis.tls.handshake;

import net.luminis.tls.TlsProtocolException;
import net.luminis.tls.extension.ExtensionParser;
import net.luminis.tls.handshake.*;

import java.io.IOException;
import java.nio.ByteBuffer;

import static net.luminis.tls.TlsConstants.HandshakeType.*;

public class TlsMessageParser {

    private final ExtensionParser customExtensionParser;

    public TlsMessageParser() {
        customExtensionParser = null;
    }

    public TlsMessageParser(ExtensionParser customExtensionParser) {
        this.customExtensionParser = customExtensionParser;
    }

    public HandshakeMessage parseAndProcessHandshakeMessage(ByteBuffer buffer, ClientMessageProcessor messageProcessor) throws TlsProtocolException, IOException {
        // https://tools.ietf.org/html/rfc8446#section-4
        // "      struct {
        //          HandshakeType msg_type;    /* handshake type */
        //          uint24 length;             /* remaining bytes in message */
        //          ...
        //      } Handshake;"
        buffer.mark();
        int messageType = buffer.get();
        int length = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        buffer.reset();

        HandshakeMessage parsedMessage;
        if (messageType == server_hello.value) {
            ServerHello sh = new ServerHello().parse(buffer, length + 4);
            parsedMessage = sh;
            messageProcessor.received(sh);
        }
        else if (messageType == encrypted_extensions.value) {
            EncryptedExtensions ee = new EncryptedExtensions().parse(buffer, length + 4, customExtensionParser);
            parsedMessage = ee;
            messageProcessor.received(ee);
        }
        else if (messageType == certificate.value) {
            CertificateMessage cm = new CertificateMessage().parse(buffer);
            parsedMessage = cm;
            messageProcessor.received(cm);
        }
        else if (messageType == certificate_verify.value) {
            CertificateVerifyMessage cv = new CertificateVerifyMessage().parse(buffer, length + 4);
            parsedMessage = cv;
            messageProcessor.received(cv);
        }
        else if (messageType == finished.value) {
            FinishedMessage fm = new FinishedMessage().parse(buffer, length + 4);
            parsedMessage = fm;
            messageProcessor.received(fm);
        }
        else if (messageType == new_session_ticket.value) {
            NewSessionTicketMessage nst = new NewSessionTicketMessage().parse(buffer, length + 4);
            parsedMessage = nst;
            messageProcessor.received(nst);
        }
        else {
            throw new TlsProtocolException("Invalid/unsupported message type (" + messageType + ")");
        }
        return parsedMessage;
    }

}
