import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.encoders.Base64;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class ECCKeyGeneration {

    public static void main(String[] args) throws Exception {

        String ecCurve =
                //"secp256r1"
                "X25519"
                // "secp192r1")
                ;

        if (ecCurve.startsWith("secp"))
            generateKeys(ecCurve);
        else
            generateXDHKeys(ecCurve);
    }

    public static ECPublicKey generateKeys(String ecCurve) throws Exception {
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec(ecCurve);
        kpg.initialize(ecsp);

        KeyPair kp = kpg.genKeyPair();
        ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();
        ECPublicKey pubKey = (ECPublicKey) kp.getPublic();

        System.out.println("private key: " + privKey.toString());
        String f = privKey.getFormat();
        System.out.println("private key: " + bytesToHex(privKey.getEncoded()));
        System.out.println("private key:" + pubKey.toString());
        String g = pubKey.getFormat();
        System.out.println("public key:" + bytesToHex(pubKey.getEncoded()));
        System.out.println("public key:" + Base64.toBase64String(pubKey.getEncoded()));
        System.out.println("public key W x: " + pubKey.getW().getAffineX());
        System.out.println("public key W x: " + pubKey.getW().getAffineX().toString(16));
        byte[] part1 = pubKey.getW().getAffineX().toByteArray();
        System.out.println("public key W y: " + pubKey.getW().getAffineY());
        System.out.println("public key params: " + pubKey.getParams());

        KeyFactory fac = KeyFactory.getInstance("EC");
        EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKey.getEncoded());
        Object restoredPrivate = fac.generatePrivate(privKeySpec);
        System.out.println(restoredPrivate);
        System.out.println("Equal? " + (privKey.equals(restoredPrivate)));

        return pubKey;
    }

    public static PublicKey generateXDHKeys(String ecCurve) throws Exception {
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("XDH");
        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec(ecCurve);
        kpg.initialize(ecsp);

        KeyPair kp = kpg.genKeyPair();
        XECPrivateKey privKey = (XECPrivateKey) kp.getPrivate();
        XECPublicKey pubKey = (XECPublicKey) kp.getPublic();

        System.out.println("private key: " + privKey.toString());
        String f = privKey.getFormat();
        System.out.println("private key: " + bytesToHex(privKey.getEncoded()));
        System.out.println("private key:" + pubKey.toString());
        String g = pubKey.getFormat();
        System.out.println("public key:" + bytesToHex(pubKey.getEncoded()));
        System.out.println("public key:" + Base64.toBase64String(pubKey.getEncoded()));
        System.out.println("public key U: " + pubKey.getU());
        System.out.println("public key U: " + pubKey.getU().toString(16));
        System.out.println("public key params: " + pubKey.getParams());

        KeyFactory fac = KeyFactory.getInstance("XDH");
        EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKey.getEncoded());
        Object restoredPrivate = fac.generatePrivate(privKeySpec);
        System.out.println(restoredPrivate);
        System.out.println("Equal? " + (privKey.equals(restoredPrivate)));

        return pubKey;
    }


    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789ABCDEF";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
    }


}
