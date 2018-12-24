package net.luminis.tls.sample;

import net.luminis.tls.ByteUtils;
import net.luminis.tls.TlsSession;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class TlsSample {

    private static PrivateKey loadPrivateKey() throws Exception {
        String encodedPrivateKey = "3041020100301306072A8648CE3D020106082A8648CE3D030107042730250201010420D08C6D445FE18034132048565FB86A3C7BD32BF72991BCDAB2117A69105C0A06";
        KeyFactory fac = KeyFactory.getInstance("EC");
        EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(ByteUtils.hexToBytes(encodedPrivateKey));
        PrivateKey restoredPrivate = fac.generatePrivate(privKeySpec);
        System.out.println(restoredPrivate);
        System.out.println("private key: " + ByteUtils.bytesToHex(restoredPrivate.getEncoded()));
        return restoredPrivate;
    }

    private static byte[] readHexDump(String filename) throws IOException {

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(TlsSample.class.getResourceAsStream(filename)))) {
            Object[] byteGroups = reader
                    .lines()
                    .map(line -> line.trim().replaceAll(" ", ""))
                    .map(ByteUtils::hexToBytes)
                    .toArray();
            int size = Arrays.stream(byteGroups).map(g -> ((byte[]) g).length).mapToInt(Integer::intValue).sum();
            byte[] result = new byte[size];
            // TODO: stream collector?
            int counter = 0;
            for (Object group: byteGroups) {
                System.arraycopy((byte[]) group, 0, result, counter, ((byte[]) group).length);
                counter += ((byte[]) group).length;
            }
            return result;
		}
    }

    public static void main(String[] args) throws Exception {
        // Security.addProvider(new BouncyCastleProvider());

        byte[] clientHello = readHexDump("clientdump.hex");
        byte[] serverReply = readHexDump("serverdump.hex");

        byte[] clientHelloMessage = new byte[clientHello.length - 5];
        System.arraycopy(clientHello, 5, clientHelloMessage, 0, clientHelloMessage.length);
        new TlsSession(clientHelloMessage, loadPrivateKey(), null, new ByteArrayInputStream(serverReply), null);
    }

}
