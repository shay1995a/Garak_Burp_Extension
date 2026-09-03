// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Runs a command to completion and collects its output. */
public final class Proc {

    public record Output(int exitCode, String stdout, String stderr, boolean timedOut) {
        public boolean ok() {
            return exitCode == 0 && !timedOut;
        }

        /** Both streams together; garak writes useful detail to each. */
        public String combined() {
            if (stdout.isEmpty()) {
                return stderr;
            }
            return stderr.isEmpty() ? stdout : stdout + "\n" + stderr;
        }
    }

    private Proc() {
    }

    public static Output run(List<String> command, Path workingDir, Map<String, String> env,
                             long timeoutSeconds) {
        ProcessBuilder builder = new ProcessBuilder(command);
        if (workingDir != null) {
            builder.directory(workingDir.toFile());
        }
        if (env != null) {
            builder.environment().putAll(env);
        }

        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            return new Output(-1, "", e.getMessage() == null ? e.toString() : e.getMessage(), false);
        }

        // Drain both pipes concurrently: a process that fills one while we block on the
        // other deadlocks, and garak is chatty on stderr.
        StringBuilder out = new StringBuilder();
        StringBuilder err = new StringBuilder();
        Thread outReader = drain(process.getInputStream(), out);
        Thread errReader = drain(process.getErrorStream(), err);

        boolean finished;
        try {
            finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return new Output(-1, out.toString(), "interrupted", true);
        }
        if (!finished) {
            process.destroyForcibly();
            join(outReader);
            join(errReader);
            return new Output(-1, out.toString(), err.toString(), true);
        }
        join(outReader);
        join(errReader);
        return new Output(process.exitValue(), out.toString().trim(), err.toString().trim(), false);
    }

    private static Thread drain(InputStream stream, StringBuilder sink) {
        Thread thread = new Thread(() -> {
            try (InputStream in = stream) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    synchronized (sink) {
                        sink.append(new String(buffer, 0, read, StandardCharsets.UTF_8));
                    }
                }
            } catch (IOException e) {
                // process gone; whatever we collected is what there is
            }
        });
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static void join(Thread thread) {
        try {
            thread.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
