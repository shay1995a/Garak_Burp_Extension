// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.garakproc;

import burp.garak.model.Finding;
import burp.garak.util.Json;
import burp.garak.util.JsonPathLite;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Follows garak's report and hit log while a run is in progress.
 *
 * <p>Tailing works because garak opens both files line-buffered ({@code buffering=1}), so a
 * line is on disk as soon as it is written. Polling rather than a WatchService: appends to
 * an already-open file are the case watch services handle worst, and a 300ms poll is well
 * inside human reaction time for a progress bar.
 */
public final class ReportTailer {

    /** garak's attempt status codes, from garak.attempt. */
    private static final int ATTEMPT_STARTED = 1;
    private static final int ATTEMPT_COMPLETE = 2;

    private static final long POLL_MILLIS = 300;

    /** Callbacks for the run controller; every one arrives on the tailer thread. */
    public interface Listener {
        /** garak has started and declared its version. */
        default void onStart(String garakVersion, String runId) {
        }

        /** One prompt has been answered by the target. */
        default void onAttemptGenerated(String probe, String prompt) {
        }

        /** One prompt has been scored by its detectors. */
        default void onAttemptEvaluated(String probe, String prompt) {
        }

        /** A probe/detector pair finished scoring. */
        default void onEval(String probe, String detector, int passed, int failed, int nones,
                            int totalEvaluated) {
        }

        /** A hit: this prompt got past this detector. */
        default void onFinding(Finding finding) {
        }

        /** garak wrote its completion record. */
        default void onCompletion() {
        }

        default void onProblem(String message) {
        }
    }

    private final Path reportFile;
    private final Path hitlogFile;
    private final Listener listener;
    private final AtomicBoolean running = new AtomicBoolean();

    private Thread thread;
    private long reportOffset;
    private long hitlogOffset;
    private volatile boolean sawCompletion;

    public ReportTailer(Path reportFile, Path hitlogFile, Listener listener) {
        this.reportFile = reportFile;
        this.hitlogFile = hitlogFile;
        this.listener = listener;
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        thread = new Thread(this::loop, "garak-report-tailer");
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * Stops tailing after one final pass, so the last lines garak wrote as it exited are
     * not lost between the process ending and the poll being cancelled.
     */
    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        drainOnce();
        if (thread != null) {
            thread.interrupt();
        }
    }

    public boolean sawCompletion() {
        return sawCompletion;
    }

    private void loop() {
        while (running.get()) {
            drainOnce();
            try {
                Thread.sleep(POLL_MILLIS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private synchronized void drainOnce() {
        reportOffset = readNewLines(reportFile, reportOffset, this::handleReportLine);
        hitlogOffset = readNewLines(hitlogFile, hitlogOffset, this::handleHitlogLine);
    }

    /**
     * Reads whole lines appended since {@code offset}, returning the new offset. A trailing
     * partial line is left for the next pass: garak may be mid-write.
     */
    private long readNewLines(Path file, long offset, java.util.function.Consumer<String> handler) {
        if (file == null || !Files.isRegularFile(file)) {
            return offset;
        }
        try (RandomAccessFile handle = new RandomAccessFile(file.toFile(), "r")) {
            long length = handle.length();
            if (length < offset) {
                offset = 0; // file was replaced; start over
            }
            if (length == offset) {
                return offset;
            }
            handle.seek(offset);
            byte[] chunk = new byte[(int) Math.min(length - offset, 8L * 1024 * 1024)];
            handle.readFully(chunk);

            int lastNewline = -1;
            for (int i = chunk.length - 1; i >= 0; i--) {
                if (chunk[i] == '\n') {
                    lastNewline = i;
                    break;
                }
            }
            if (lastNewline < 0) {
                return offset; // no complete line yet
            }
            String text = new String(chunk, 0, lastNewline + 1, StandardCharsets.UTF_8);
            for (String line : text.split("\n")) {
                if (!line.isBlank()) {
                    handler.accept(line);
                }
            }
            return offset + lastNewline + 1;
        } catch (IOException e) {
            listener.onProblem("could not read " + file.getFileName() + ": " + e.getMessage());
            return offset;
        }
    }

    // ---------------------------------------------------------------- report.jsonl

    private void handleReportLine(String line) {
        Optional<JsonObject> parsed = Json.parseObject(line);
        if (parsed.isEmpty()) {
            return;
        }
        JsonObject record = parsed.get();
        switch (Json.string(record, "entry_type", "")) {
            case "init" -> listener.onStart(
                    Json.string(record, "garak_version", "?"),
                    Json.string(record, "run", ""));
            case "attempt" -> handleAttempt(record);
            case "eval" -> listener.onEval(
                    Json.string(record, "probe", ""),
                    Json.string(record, "detector", ""),
                    Json.integer(record, "passed", 0),
                    Json.integer(record, "fails", 0),
                    Json.integer(record, "nones", 0),
                    Json.integer(record, "total_evaluated", 0));
            case "completion" -> {
                sawCompletion = true;
                listener.onCompletion();
            }
            default -> {
                // start_run setup, probe_summary, plugin_cache, tree_data, digest
            }
        }
    }

    private void handleAttempt(JsonObject record) {
        String probe = Json.string(record, "probe_classname", "");
        String prompt = promptText(record.get("prompt"));
        int status = Json.integer(record, "status", 0);
        if (status == ATTEMPT_STARTED) {
            listener.onAttemptGenerated(probe, prompt);
        } else if (status == ATTEMPT_COMPLETE) {
            listener.onAttemptEvaluated(probe, prompt);
        }
    }

    // ---------------------------------------------------------------- hitlog.jsonl

    private void handleHitlogLine(String line) {
        Optional<JsonObject> parsed = Json.parseObject(line);
        if (parsed.isEmpty()) {
            return;
        }
        JsonObject record = parsed.get();

        Finding finding = new Finding();
        finding.probe = Json.string(record, "probe", "");
        finding.detector = Json.string(record, "detector", "");
        finding.goal = Json.string(record, "goal", "");
        finding.prompt = promptText(record.get("prompt"));
        finding.output = messageText(record.get("output"));
        finding.attemptId = Json.string(record, "attempt_id", "");
        finding.attemptSeq = Json.integer(record, "attempt_seq", 0);
        finding.attemptIdx = Json.integer(record, "attempt_idx", 0);
        finding.triggers = triggersText(record.get("triggers"));
        JsonElement score = record.get("score");
        if (score != null && score.isJsonPrimitive()) {
            try {
                finding.score = score.getAsDouble();
            } catch (NumberFormatException e) {
                finding.score = 0;
            }
        }
        listener.onFinding(finding);
    }

    // ------------------------------------------------------------------- decoding

    /**
     * Pulls the prompt text out of a serialised garak Conversation.
     *
     * <p>The shape is {@code {"turns": [{"role": ..., "content": {"text": ...}}], ...}} and
     * the prompt under test is the last turn. Older records serialise a plain string, so
     * both are handled.
     */
    public static String promptText(JsonElement prompt) {
        if (prompt == null || prompt.isJsonNull()) {
            return "";
        }
        if (prompt.isJsonPrimitive()) {
            return prompt.getAsString();
        }
        if (!prompt.isJsonObject()) {
            return "";
        }
        JsonObject object = prompt.getAsJsonObject();
        return JsonPathLite.evalToString(object, "$.turns[-1].content.text")
                .filter(text -> !text.isEmpty())
                .or(() -> JsonPathLite.evalToString(object, "$.turns[-1].content"))
                .or(() -> JsonPathLite.evalToString(object, "$.text"))
                .orElse("");
    }

    /** A garak Message serialises as {@code {"text": ..., "lang": ...}}. */
    public static String messageText(JsonElement message) {
        if (message == null || message.isJsonNull()) {
            return "";
        }
        if (message.isJsonPrimitive()) {
            return message.getAsString();
        }
        if (message.isJsonObject()) {
            return Json.string(message.getAsJsonObject(), "text", "");
        }
        return "";
    }

    private static String triggersText(JsonElement triggers) {
        if (triggers == null || triggers.isJsonNull()) {
            return "";
        }
        if (triggers.isJsonPrimitive()) {
            return triggers.getAsString();
        }
        if (triggers.isJsonArray()) {
            StringBuilder out = new StringBuilder();
            triggers.getAsJsonArray().forEach(element -> {
                if (out.length() > 0) {
                    out.append(", ");
                }
                out.append(element.isJsonPrimitive() ? element.getAsString() : element.toString());
            });
            return out.toString();
        }
        return triggers.toString();
    }
}
