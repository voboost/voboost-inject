package ru.voboost.agents;

/** Minimal copy of the production agent logging seam for emulator fixtures. */
public final class Log {
    private static final int INFO = 2;

    private Log() {}

    private static native void log(long timestampMs, int level, String source, String message);

    public static void info(String source, String message) {
        try {
            log(System.currentTimeMillis(), INFO, source, message);
        } catch (Throwable ignored) {
            // Logging must never break the seam test.
        }
    }
}
