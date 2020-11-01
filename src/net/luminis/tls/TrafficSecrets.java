package net.luminis.tls;

public interface TrafficSecrets {

    byte[] getClientEarlyTrafficSecret();

    byte[] getClientHandshakeTrafficSecret();

    byte[] getServerHandshakeTrafficSecret();

    byte[] getClientApplicationTrafficSecret();

    byte[] getServerApplicationTrafficSecret();

}
