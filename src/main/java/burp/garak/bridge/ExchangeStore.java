// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.bridge;

import burp.garak.model.Exchange;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Every request the bridge made, indexed so a garak finding can be traced back to it.
 *
 * <p>garak's hit log names the prompt but knows nothing about HTTP, so correlation runs
 * through the prompt text. When {@code generations > 1} the same prompt is sent several
 * times and the hit log's {@code attempt_idx} picks which of those exchanges to show,
 * which is why the index keeps an ordered list per prompt rather than a single entry.
 */
public final class ExchangeStore {

    private final AtomicLong nextId = new AtomicLong(1);
    private final Map<Long, Exchange> byId = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> byPrompt = new ConcurrentHashMap<>();
    private final List<Consumer<Exchange>> listeners = new CopyOnWriteArrayList<>();

    /** Starts recording a prompt; the returned exchange is filled in as the request runs. */
    public Exchange open(String prompt) {
        Exchange exchange = new Exchange(nextId.getAndIncrement(), prompt);
        byId.put(exchange.id, exchange);
        byPrompt.computeIfAbsent(key(prompt), k -> new CopyOnWriteArrayList<>()).add(exchange.id);
        return exchange;
    }

    /** Marks an exchange finished and notifies the UI. */
    public void close(Exchange exchange) {
        listeners.forEach(listener -> listener.accept(exchange));
    }

    /**
     * Finds the exchange for a prompt, picking the {@code attemptIdx}-th send when the same
     * prompt went out more than once. Falls back to the first send when the index is out of
     * range, which is better than showing no traffic at all.
     */
    public Optional<Exchange> find(String prompt, int attemptIdx) {
        List<Long> ids = byPrompt.get(key(prompt));
        if (ids == null || ids.isEmpty()) {
            return Optional.empty();
        }
        int index = attemptIdx >= 0 && attemptIdx < ids.size() ? attemptIdx : 0;
        return Optional.ofNullable(byId.get(ids.get(index)));
    }

    public Optional<Exchange> byId(long id) {
        return Optional.ofNullable(byId.get(id));
    }

    /** Snapshot in send order, for the traffic table. */
    public List<Exchange> all() {
        List<Exchange> snapshot = new ArrayList<>(byId.values());
        snapshot.sort((a, b) -> Long.compare(a.id, b.id));
        return snapshot;
    }

    public int size() {
        return byId.size();
    }

    public long counted(Exchange.Status status) {
        return byId.values().stream().filter(exchange -> exchange.status == status).count();
    }

    public void addListener(Consumer<Exchange> listener) {
        listeners.add(listener);
    }

    public void clear() {
        byId.clear();
        byPrompt.clear();
        nextId.set(1);
    }

    /**
     * Normalises whitespace for matching. garak round-trips prompts through JSON and its
     * own Message objects, and line endings do not always survive intact; matching on the
     * exact bytes loses correlations that are obviously the same prompt.
     */
    private static String key(String prompt) {
        return prompt == null ? "" : prompt.replace("\r\n", "\n").trim();
    }
}
