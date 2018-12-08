package net.luminis.tls;

import java.io.IOException;
import java.io.PushbackInputStream;

public class Alert {

    public void parse(PushbackInputStream input) throws IOException, TlsProtocolException {
        input.read();  // type
        int versionHigh = input.read();
        int versionLow = input.read();
        if (versionHigh != 3 || versionLow != 3)
            throw new TlsProtocolException("Invalid version number (should be 0x0303");
        int length = (input.read() << 8) | input.read();
        if (length != 2)
            throw new TlsProtocolException("Invalid alert length (" + length + ")");

        int alertLevel = input.read();
        int alertDescription = input.read();
        if (alertLevel == 2 && alertDescription == 40) {
            System.out.println("Alert fatal/handshake_failure");
        }
        else
            System.out.println("Alert " + alertLevel + "/" + alertDescription);
    }
}
