package net.luminis.tls;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;

public class AlertRecord {

    public void parse(PushbackInputStream input) throws IOException, TlsProtocolException {
        input.read();  // type
        int versionHigh = input.read();
        int versionLow = input.read();
        if (versionHigh != 3 || versionLow != 3)
            throw new TlsProtocolException("Invalid version number (should be 0x0303");
        int length = (input.read() << 8) | input.read();
        if (length != 2)
            throw new TlsProtocolException("Invalid alert length (" + length + ")");

        ByteBuffer buffer = ByteBuffer.allocate(length);
        input.read(buffer.array());

        parseAlertMessage(buffer);
    }

    public static void parseAlertMessage(ByteBuffer buffer) throws TlsProtocolException {
        int alertLevel = buffer.get();
        int alertDescription = buffer.get();
        if (alertLevel == 2 && alertDescription == 40) {
            Logger.debug("AlertRecord fatal/handshake_failure");
        }
        else {
            Logger.debug("AlertRecord " + alertLevel + "/" + alertDescription);
        }
    }
}
