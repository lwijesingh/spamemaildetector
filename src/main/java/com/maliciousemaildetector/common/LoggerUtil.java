package com.maliciousemaildetector.common;

import java.util.logging.Level;
import java.util.logging.Logger;

public class LoggerUtil {
    private static Logger logger = Logger.getAnonymousLogger();
    public static int logLevel = 3;

    public LoggerUtil() {
    }

    public static void setLogLevel() {
        switch(logLevel) {
            case 0:
                logger.setLevel(Level.OFF);
            case 1:
            default:
                break;
            case 2:
                logger.setLevel(Level.WARNING);
                break;
            case 3:
                logger.setLevel(Level.INFO);
        }

    }

    public static void logINFO(String logMessage) {
        setLogLevel();
        logger.log(Level.INFO, logMessage);
    }

    public static void logERROR(String logMessage, Throwable throwable) {
        setLogLevel();
        if (throwable != null) {
            logger.log(Level.SEVERE, logMessage, throwable);
        } else {
            logger.log(Level.SEVERE, logMessage);
        }

    }

    public static void logWARNING(String logMessage, Throwable throwable) {
        setLogLevel();
        if (throwable != null) {
            logger.log(Level.WARNING, logMessage, throwable);
        } else {
            logger.log(Level.WARNING, logMessage);
        }

    }
}
