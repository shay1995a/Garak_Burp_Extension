// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Checks the built jar the way Burp's loader will see it.
 *
 * <p>Burp auto-detects "any class that extends BurpExtension", instantiates it with its
 * no-arg constructor, and provides the Montoya API itself. So the things that can go wrong
 * at load time and nowhere else are: no entry class, more than one, an entry class that
 * cannot be constructed, a missing bundled dependency, or -- the nasty one -- a bundled
 * copy of montoya-api shadowing Burp's own.
 */
public final class JarLoadTest {

    private static int passed;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        File jar = new File(args.length > 0 ? args[0] : "build/garak-bridge.jar");
        ok("jar exists at " + jar, jar.isFile());

        List<String> classNames = new ArrayList<>();
        boolean bundlesGson = false;
        boolean bundlesMontoya = false;

        try (JarFile jarFile = new JarFile(jar)) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (name.startsWith("com/google/gson/")) {
                    bundlesGson = true;
                }
                if (name.startsWith("burp/api/montoya/")) {
                    bundlesMontoya = true;
                }
                if (name.endsWith(".class") && !name.contains("$")) {
                    classNames.add(name.replace('/', '.')
                            .substring(0, name.length() - ".class".length()));
                }
            }
        }

        ok("Gson is bundled (Burp does not provide it)", bundlesGson);
        ok("montoya-api is NOT bundled (Burp provides it; a copy would shadow Burp's)",
                !bundlesMontoya);

        // Burp puts montoya-api on the extension's classpath, so mirror that here.
        URL[] classpath = {
                jar.toURI().toURL(),
                new File("lib/montoya-api-2026.7.jar").toURI().toURL()
        };

        List<Class<?>> entryPoints = new ArrayList<>();
        try (URLClassLoader loader = new URLClassLoader(classpath, null)) {
            Class<?> burpExtension = loader.loadClass("burp.api.montoya.BurpExtension");
            for (String className : classNames) {
                try {
                    Class<?> candidate = loader.loadClass(className);
                    if (burpExtension.isAssignableFrom(candidate) && !candidate.isInterface()) {
                        entryPoints.add(candidate);
                    }
                } catch (Throwable e) {
                    // A class that will not even link is a real problem; report it.
                    failures.add("could not load " + className + ": " + e);
                    System.out.println("  FAIL could not load " + className + ": " + e);
                }
            }

            is("exactly one entry point", 1, entryPoints.size());
            if (entryPoints.size() == 1) {
                Class<?> entry = entryPoints.get(0);
                is("entry point is GarakExtension", "burp.garak.GarakExtension", entry.getName());
                Object instance = entry.getDeclaredConstructor().newInstance();
                ok("entry point constructs with a no-arg constructor", instance != null);
            }

            // The classes Burp will touch first must link cleanly under a plain classloader.
            for (String required : List.of(
                    "burp.garak.GarakContext",
                    "burp.garak.ui.GarakTab",
                    "burp.garak.capture.ContextMenu",
                    "burp.garak.bridge.BridgeServer",
                    "burp.garak.garakproc.RunController")) {
                ok(required + " links", loader.loadClass(required) != null);
            }
        }

        System.out.println();
        System.out.println(passed + " passed, " + failures.size() + " failed");
        failures.forEach(failure -> System.out.println("  FAIL " + failure));
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    private static void ok(String what, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  ok   " + what);
        } else {
            failures.add(what);
            System.out.println("  FAIL " + what);
        }
    }

    private static void is(String what, Object expected, Object actual) {
        if (expected.equals(actual)) {
            passed++;
            System.out.println("  ok   " + what);
        } else {
            failures.add(what + " (expected " + expected + ", got " + actual + ")");
            System.out.println("  FAIL " + what + ": expected " + expected + ", got " + actual);
        }
    }

    private static void is(String what, int expected, int actual) {
        is(what, Integer.valueOf(expected), Integer.valueOf(actual));
    }
}
