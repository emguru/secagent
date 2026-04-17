package dev.agentsec.ui.scan;

import jakarta.validation.constraints.NotBlank;

import java.util.ArrayList;
import java.util.List;

/**
 * Request body for POST /api/scan. Targets must match IDs from GET /api/targets (Python agentsec.targets).
 */
public class ScanRequest {

    @NotBlank
    private String path = "";

    private List<String> targets = new ArrayList<>();

    private boolean focusTargets;

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public List<String> getTargets() {
        return targets;
    }

    public void setTargets(List<String> targets) {
        this.targets = targets != null ? new ArrayList<>(targets) : new ArrayList<>();
    }

    public boolean isFocusTargets() {
        return focusTargets;
    }

    public void setFocusTargets(boolean focusTargets) {
        this.focusTargets = focusTargets;
    }
}
