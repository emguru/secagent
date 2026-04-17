package dev.agentsec.ui.scan;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Consumer;

@Component
public class PythonScannerRunner {

    private final Path scannerRoot;

    public PythonScannerRunner(
            @Value("${agentsec.scanner-root:}") String configuredScannerRoot
    ) {
        if (configuredScannerRoot != null && !configuredScannerRoot.isBlank()) {
            this.scannerRoot = Path.of(configuredScannerRoot).toAbsolutePath().normalize();
        } else {
            this.scannerRoot = defaultScannerRoot();
        }
    }

    private static Path defaultScannerRoot() {
        Path cwd = Path.of("").toAbsolutePath();
        Path sibling = cwd.resolve("scanner");
        if (Files.isDirectory(sibling)) {
            return sibling.normalize();
        }
        Path parentSibling = cwd.getParent() != null ? cwd.getParent().resolve("scanner") : null;
        if (parentSibling != null && Files.isDirectory(parentSibling)) {
            return parentSibling.normalize();
        }
        return sibling;
    }

    public Path getScannerRoot() {
        return scannerRoot;
    }

    /**
     * Runs Python module {@code agentsec} and invokes {@code lineConsumer} for each stdout line (NDJSON).
     */
    public int runNdjsonScan(
            String projectPath,
            List<String> targets,
            boolean focusTargets,
            Consumer<String> lineConsumer
    ) throws IOException, InterruptedException {
        Path target = Path.of(projectPath).toAbsolutePath().normalize();
        if (!Files.isDirectory(target)) {
            throw new IllegalArgumentException("Not a directory: " + target);
        }

        List<String> command = buildCommand(target, targets, focusTargets);
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        pb.environment().put("PYTHONUTF8", "1");
        pb.environment().put("PYTHONIOENCODING", "utf-8");
        if (Files.isDirectory(scannerRoot)) {
            pb.directory(scannerRoot.toFile());
            pb.environment().put("PYTHONPATH", scannerRoot.toString());
        }

        Process process = pb.start();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lineConsumer.accept(line);
            }
        }
        return process.waitFor();
    }

    private List<String> buildCommand(Path target, List<String> targets, boolean focusTargets) {
        List<String> launcher = resolvePythonLauncher().orElseThrow(() -> new IllegalStateException(
                "Could not find Python on PATH. Install Python 3.10+ and ensure python/python3 (or Windows `py -3`) works."
        ));
        List<String> cmd = new ArrayList<>(launcher);
        cmd.add("-m");
        cmd.add("agentsec");
        cmd.add("--path");
        cmd.add(target.toString());
        cmd.add("--format");
        cmd.add("ndjson");
        if (targets != null && !targets.isEmpty()) {
            cmd.add("--targets");
            cmd.add(String.join(",", targets));
        }
        if (focusTargets) {
            cmd.add("--focus");
        }
        return cmd;
    }

    private Optional<List<String>> resolvePythonLauncher() {
        boolean win = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows");
        List<List<String>> candidates = new ArrayList<>();
        if (win) {
            candidates.add(List.of("py", "-3"));
            candidates.add(List.of("python"));
            candidates.add(List.of("python3"));
        } else {
            candidates.add(List.of("python3"));
            candidates.add(List.of("python"));
        }
        for (List<String> c : candidates) {
            if (pythonWorks(c)) {
                return Optional.of(c);
            }
        }
        return Optional.empty();
    }

    private boolean pythonWorks(List<String> launcherPrefix) {
        List<String> probe = new ArrayList<>(launcherPrefix);
        probe.add("-c");
        probe.add("print(1)");
        try {
            ProcessBuilder pb = new ProcessBuilder(probe);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
