package net.luminis.tls;

public class Logger {

    private static boolean enabled = false;

    public static void enableDebugLogging(boolean enable) {
        enabled = enable;
    }

    public static void debug(String message) {
        if (enabled) {
            System.out.println(message);
        }
    }
}
