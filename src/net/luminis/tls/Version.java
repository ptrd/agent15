package net.luminis.tls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Version {

    public static void main(String[] args) {
        System.out.println(getVersion());
    }

    public static String getVersion() {
        InputStream in = Version.class.getResourceAsStream("version.properties");
        if (in != null) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
                return reader.readLine();
            } catch (IOException e) {
                throw new RuntimeException("unknown version");
            }
        }
        else {
            throw new RuntimeException("unknown version");
        }
    }
}
