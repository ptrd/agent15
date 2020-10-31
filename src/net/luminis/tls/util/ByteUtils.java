package net.luminis.tls.util;

import java.nio.ByteBuffer;

public class ByteUtils {

    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789abcdef";
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

    public static String bytesToHex(byte[] data, int offset, int length) {
        String digits = "0123456789abcdef";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[offset+i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String byteToHexBlock(byte[] data) {
        return byteToHexBlock(data, data.length);
    }

    public static String byteToHexBlock(byte[] data, int length) {
        String result = "";
        for (int i = 0; i < length; ) {
            result += (String.format("%02x ", data[i]));
            i++;
            if (i < data.length)
            if (i % 16 == 0)
                result += "\n";
            else if (i % 8 == 0)
                result += " ";
        }
        return result;
    }

    public static String byteToHexBlock(ByteBuffer data, int start, int size) {
        int initialPosition = data.position();
        data.position(start);
        byte[] dataBytes = new byte[size];
        data.get(dataBytes);
        data.position(initialPosition);
        return byteToHexBlock(dataBytes);
    }

    public static byte[] hexToBytes(String hex) {
        hex = hex.replace(" ", "");
        int length = hex.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character
                    .digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

}
