package net.luminis.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

public class TlsSession {


    private final byte[] sentClientHello;
    private final PrivateKey clientPrivateKey;
    private final PublicKey clientPublicKey;
    private final InputStream input;
    private final TlsState state;

    public TlsSession(byte[] sentClientHello, PrivateKey clientPrivateKey, PublicKey clientPublicKey, InputStream input) throws IOException, TlsProtocolException {

        this.sentClientHello = sentClientHello;
        this.clientPrivateKey = clientPrivateKey;
        this.clientPublicKey = clientPublicKey;
        this.input = input;

        state = new TlsState();
        state.clientHelloSend(clientPrivateKey, sentClientHello);
        parseServerMessages(new PushbackInputStream(input, 16));
    }

    private void parseServerMessages(PushbackInputStream input) throws IOException, TlsProtocolException {
        int contentType = input.read();

        while (contentType != -1) {
            input.unread(contentType);

            switch (contentType) {
                case 0:
                    throw new RuntimeException("Record type is 0 (invalid)");
                case 20:
                    new ChangeCipherSpec().parse(input);
                    break;
                case 21:
                    new Alert().parse(input);
                    break;
                case 22:
                    new HandshakeRecord().parse(input, state);
                    break;
                case 23:
                    new ApplicationData().parse(input, state);
                    break;
                default:
                    throw new RuntimeException("Record type is unknown (" + contentType + ")");
            }
            contentType = input.read();
        }
    }

}
