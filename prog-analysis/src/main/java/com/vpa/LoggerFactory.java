package com.vpa;

import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.LogRecord;

public class LoggerFactory {
    private static final Logger logger = Logger.getLogger("GlobalLogger");

    static {
        // Create ConsoleHandler
        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.INFO);
        consoleHandler.setFormatter(new SimpleFormatter() {
            // private static final String vpaFormat = "[%4$s] [%2$s] %5$s %n";
            private static final String vpaFormat = "[%4$s] %5$s %n";

            @Override
            public synchronized String format(LogRecord lr) {
                return String.format(vpaFormat,
                        lr.getMillis(),
                        lr.getSourceClassName(),
                        lr.getLoggerName(),
                        lr.getLevel().getLocalizedName(),
                        lr.getMessage()
                );
            }
        });

        // Configure Logger
        logger.setLevel(Level.INFO);
        logger.addHandler(consoleHandler);
        logger.setUseParentHandlers(false);
    }

    public static Logger getLogger() {
        return logger;
    }
}
