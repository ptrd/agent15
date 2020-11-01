package net.luminis.tls.alert;

import net.luminis.tls.TlsProtocolException;

public class DecodeErrorException extends TlsProtocolException {

    /**
     * Exception representing TLS error alert "decode_error".
     * See https://www.davidwong.fr/tls13/#section-6.2
     * "decode_error: A message could not be decoded because some field was out of the specified range or the length of
     * the message was incorrect. This alert is used for errors where the message does not conform to the formal
     * protocol syntax."
     * @param message
     */
    public DecodeErrorException(String message) {
        super(message);
    }
}
