package dev.agentsec.ui.scan;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class ScanController {

    private final PythonScannerRunner runner;
    private final ObjectMapper objectMapper;

    public ScanController(PythonScannerRunner runner, ObjectMapper objectMapper) {
        this.runner = runner;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/api/health")
    public HealthResponse health() {
        return new HealthResponse("ok", runner.getScannerRoot().toString());
    }

    @PostMapping(value = "/api/scan", produces = "application/x-ndjson")
    public ResponseEntity<StreamingResponseBody> scan(@Valid @RequestBody ScanRequest request) {
        StreamingResponseBody body = outputStream -> {
            try {
                var writer = new java.io.OutputStreamWriter(outputStream, StandardCharsets.UTF_8);
                int code = runner.runNdjsonScan(
                        request.getPath(),
                        request.getTargets(),
                        request.isFocusTargets(),
                        line -> {
                            try {
                                writer.write(line);
                                writer.write('\n');
                                writer.flush();
                            } catch (java.io.IOException e) {
                                throw new RuntimeException(e);
                            }
                        });
                if (code != 0) {
                    writer.write(errorLine("Scanner process exited with code " + code));
                    writer.flush();
                }
            } catch (IllegalArgumentException e) {
                writeRaw(outputStream, errorLine(e.getMessage() == null ? "invalid path" : e.getMessage()));
            } catch (Exception e) {
                writeRaw(outputStream, errorLine(e.getMessage() == null ? "scan failed" : e.getMessage()));
            }
        };
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.parseMediaType("application/x-ndjson"))
                .body(body);
    }

    private String errorLine(String message) {
        try {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("type", "error");
            m.put("message", message);
            return objectMapper.writeValueAsString(m) + "\n";
        } catch (Exception e) {
            return "{\"type\":\"error\",\"message\":\"scan failed\"}\n";
        }
    }

    private void writeRaw(java.io.OutputStream outputStream, String line) {
        try {
            outputStream.write(line.getBytes(StandardCharsets.UTF_8));
        } catch (java.io.IOException ignored) {
        }
    }

    public record HealthResponse(String status, String scannerRoot) {
    }
}
