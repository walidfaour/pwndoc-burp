/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.context;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.walidfaour.pwndoc.api.ApiResult;
import com.walidfaour.pwndoc.api.PwnDocApiClient;
import com.walidfaour.pwndoc.api.PwnDocApiClient.CustomField;
import com.walidfaour.pwndoc.config.ConfigManager;
import com.walidfaour.pwndoc.util.Cvss31Calculator;
import com.walidfaour.pwndoc.util.Cvss31Calculator.CvssResult;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Tabbed editor panel for finding details.
 * Contains Definition, Proofs, and Details tabs.
 * 
 * FIXES IMPLEMENTED:
 * - Dynamic custom fields filtered by audit type (displaySub matching)
 * - No internal scrolling - parent handles scroll for entire panel
 * - File upload with proper status tracking for multiple files
 * - Agnostic to PwnDoc instance configuration
 */
public class FindingEditorPanel extends JPanel {
    
    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final PwnDocApiClient apiClient;
    private final Logging logging;
    private final PwnDocContextMenuProvider.RequestContext requestContext;
    
    private JTabbedPane tabbedPane;
    
    // Definition tab
    private JTextField titleField;
    private JComboBox<String> typeCombo;
    private JTextArea descriptionArea;
    private JTextArea observationArea;
    private JTextArea referencesArea;
    
    // Custom fields panel for findings - dynamically filtered by audit type
    private JPanel customFieldsPanel;
    private Map<String, JComponent> customFieldComponents = new HashMap<>();
    private Map<String, String> customFieldTypes = new HashMap<>();
    private Map<String, String> customFieldIds = new HashMap<>();  // label -> id mapping
    private List<CustomField> allCustomFields = new ArrayList<>();
    
    // Audit type for filtering custom fields (e.g., "Web_Application_Audit" -> "WEB")
    private String currentAuditType;
    private String currentDisplaySub;
    
    // Proofs tab
    private DefaultListModel<FileEntry> proofsListModel;
    private JList<FileEntry> proofsList;
    private List<File> uploadQueue = new ArrayList<>();
    
    // Details tab
    private JTextArea affectedAssetsArea;
    private JComboBox<String> remediationDifficultyCombo;
    private JComboBox<String> priorityCombo;
    private JTextArea remediationArea;
    
    // CVSS section
    private JComboBox<String> cvssMode;
    private JPanel cvssManualPanel;
    private JComboBox<String> severityDropdown;
    private JLabel cvssScoreLabel;
    private JLabel impactLabel;
    private JLabel exploitabilityLabel;
    
    // CVSS metric buttons - store references
    private Map<String, String> cvssMetrics = new HashMap<>();
    private Map<String, List<JButton>> cvssButtons = new HashMap<>();
    
    private String currentFindingId;
    private String existingPoc;  // Preserve existing proofs when updating
    private JsonObject currentVulnerability;
    
    public FindingEditorPanel(MontoyaApi api, ConfigManager configManager,
                              PwnDocApiClient apiClient, Logging logging,
                              PwnDocContextMenuProvider.RequestContext requestContext) {
        this.api = api;
        this.configManager = configManager;
        this.apiClient = apiClient;
        this.logging = logging;
        this.requestContext = requestContext;
        
        initializeUI();
        loadCustomFields();
    }
    
    /**
     * Set the audit type for custom field filtering.
     * Call this before showing the panel to filter custom fields appropriately.
     * 
     * @param auditType The audit type (e.g., "Web_Application_Audit", "Mobile_Application_Audit")
     */
    public void setAuditType(String auditType) {
        this.currentAuditType = auditType;
        this.currentDisplaySub = mapAuditTypeToDisplaySub(auditType);
        logging.logToOutput("Set audit type: " + auditType + " -> displaySub: " + currentDisplaySub);
        
        // Rebuild custom fields panel with new filter
        if (!allCustomFields.isEmpty()) {
            buildCustomFieldsPanel();
        }
    }
    
    /**
     * Maps audit type name to displaySub value.
     * This mapping is derived dynamically from common patterns in PwnDoc.
     * Falls back to extracting keywords if no exact match.
     */
    private String mapAuditTypeToDisplaySub(String auditType) {
        if (auditType == null || auditType.isEmpty()) {
            return "";
        }
        
        String lower = auditType.toLowerCase();
        
        // Common mappings based on audit type naming patterns
        if (lower.contains("web") && !lower.contains("mobile")) {
            return "WEB";
        } else if (lower.contains("mobile")) {
            return "MOBILE";
        } else if (lower.contains("api") && !lower.contains("application")) {
            return "API";
        } else if (lower.contains("network") || lower.contains("infra")) {
            return "NETWORK";
        } else if (lower.contains("wifi") || lower.contains("wireless")) {
            return "WIFI";
        } else if (lower.contains("source") && lower.contains("code")) {
            return "Code";
        } else if (lower.contains("waf")) {
            return "WAF";
        } else if (lower.contains("phishing")) {
            return "PHISHING";
        } else if (lower.contains("desktop")) {
            return "DESKTOP";
        } else if (lower.contains("system")) {
            return "SYSTEM";
        } else if (lower.contains("email")) {
            return "EMAIL";
        } else if (lower.contains("controller")) {
            return "WIRELESS_CONTROLLER";
        } else if (lower.contains("architecture")) {
            return "Architecture Review";
        }
        
        // Fallback: extract first meaningful word
        String[] parts = auditType.split("[_\\s]+");
        if (parts.length > 0) {
            return parts[0].toUpperCase();
        }
        
        return "";
    }
    
    private void initializeUI() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Finding Editor"));
        
        tabbedPane = new JTabbedPane();
        
        // Create tabs WITHOUT internal scroll panes - parent will handle scrolling
        tabbedPane.addTab("Definition", createDefinitionTab());
        tabbedPane.addTab("Proofs", createProofsTab());
        tabbedPane.addTab("Details", createDetailsTab());
        
        add(tabbedPane, BorderLayout.CENTER);
    }
    
    /**
     * Definition tab - NO internal scrolling.
     * Content is laid out vertically and parent will scroll entire editor.
     */
    private JPanel createDefinitionTab() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Standard fields
        JPanel fieldsPanel = new JPanel(new GridBagLayout());
        fieldsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Title
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.weightx = 0;
        fieldsPanel.add(new JLabel("Title: *"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        titleField = new JTextField(40);
        fieldsPanel.add(titleField, gbc);
        
        // Type
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.weightx = 0;
        fieldsPanel.add(new JLabel("Type: *"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        typeCombo = new JComboBox<>(getVulnerabilityTypes());
        fieldsPanel.add(typeCombo, gbc);
        
        // Description
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        fieldsPanel.add(new JLabel("Description: *"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        descriptionArea = new JTextArea(4, 40);
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        JScrollPane descScroll = new JScrollPane(descriptionArea);
        descScroll.setPreferredSize(new Dimension(400, 80));
        descScroll.setMinimumSize(new Dimension(300, 60));
        fieldsPanel.add(descScroll, gbc);
        
        // Observation
        gbc.gridx = 0; gbc.gridy = 3;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        fieldsPanel.add(new JLabel("Observation:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        observationArea = new JTextArea(3, 40);
        observationArea.setLineWrap(true);
        observationArea.setWrapStyleWord(true);
        JScrollPane obsScroll = new JScrollPane(observationArea);
        obsScroll.setPreferredSize(new Dimension(400, 60));
        obsScroll.setMinimumSize(new Dimension(300, 50));
        fieldsPanel.add(obsScroll, gbc);
        
        // References
        gbc.gridx = 0; gbc.gridy = 4;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        fieldsPanel.add(new JLabel("References:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        referencesArea = new JTextArea(2, 40);
        referencesArea.setLineWrap(true);
        referencesArea.setWrapStyleWord(true);
        JScrollPane refScroll = new JScrollPane(referencesArea);
        refScroll.setPreferredSize(new Dimension(400, 50));
        refScroll.setMinimumSize(new Dimension(300, 40));
        fieldsPanel.add(refScroll, gbc);
        
        fieldsPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, fieldsPanel.getPreferredSize().height));
        panel.add(fieldsPanel);
        
        // Add some spacing
        panel.add(Box.createVerticalStrut(15));
        
        // Custom fields section
        JPanel customSection = new JPanel(new BorderLayout());
        customSection.setAlignmentX(Component.LEFT_ALIGNMENT);
        customSection.setBorder(BorderFactory.createTitledBorder("Custom Fields"));
        
        customFieldsPanel = new JPanel();
        customFieldsPanel.setLayout(new BoxLayout(customFieldsPanel, BoxLayout.Y_AXIS));
        
        // Initial message
        JLabel loadingLabel = new JLabel("Loading custom fields...");
        loadingLabel.setForeground(Color.GRAY);
        customFieldsPanel.add(loadingLabel);
        
        customSection.add(customFieldsPanel, BorderLayout.CENTER);
        panel.add(customSection);
        
        return panel;
    }
    
    /**
     * Proofs tab - file upload area
     */
    private JPanel createProofsTab() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Info label - plain text (no HTML)
        JLabel infoLabel = new JLabel("Upload evidence files (screenshots, logs, etc.)");
        infoLabel.setForeground(Color.GRAY);
        panel.add(infoLabel, BorderLayout.NORTH);
        
        // File list
        proofsListModel = new DefaultListModel<>();
        proofsList = new JList<>(proofsListModel);
        proofsList.setCellRenderer(new FileEntryRenderer());
        proofsList.setVisibleRowCount(6);
        
        JScrollPane scrollPane = new JScrollPane(proofsList);
        scrollPane.setPreferredSize(new Dimension(400, 150));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton uploadButton = new JButton("Upload Files...");
        uploadButton.addActionListener(e -> selectFilesToUpload());
        
        JButton removeButton = new JButton("Remove Selected");
        removeButton.addActionListener(e -> removeSelectedProof());
        
        JButton clearButton = new JButton("Clear All");
        clearButton.addActionListener(e -> clearAllProofs());
        
        buttonPanel.add(uploadButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(clearButton);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * Details tab - NO internal scrolling, just vertical layout.
     */
    private JPanel createDetailsTab() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Standard detail fields
        JPanel fieldsPanel = new JPanel(new GridBagLayout());
        fieldsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Affected Assets / Scope
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        fieldsPanel.add(new JLabel("Affected Assets:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        affectedAssetsArea = new JTextArea(2, 40);
        affectedAssetsArea.setLineWrap(true);
        affectedAssetsArea.setWrapStyleWord(true);
        
        // Pre-populate from request context if available
        if (requestContext != null && requestContext.url != null && !requestContext.url.isEmpty()) {
            affectedAssetsArea.setText(requestContext.url);
        }
        
        JScrollPane assetsScroll = new JScrollPane(affectedAssetsArea);
        assetsScroll.setPreferredSize(new Dimension(400, 50));
        fieldsPanel.add(assetsScroll, gbc);
        
        // Remediation Difficulty
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;
        fieldsPanel.add(new JLabel("Remediation Difficulty:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        remediationDifficultyCombo = new JComboBox<>(new String[]{"Easy", "Medium", "Hard"});
        remediationDifficultyCombo.setSelectedIndex(1);
        fieldsPanel.add(remediationDifficultyCombo, gbc);
        
        // Priority
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.weightx = 0;
        fieldsPanel.add(new JLabel("Priority:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        priorityCombo = new JComboBox<>(new String[]{"1 - Critical", "2 - High", "3 - Medium", "4 - Low"});
        priorityCombo.setSelectedIndex(2);
        fieldsPanel.add(priorityCombo, gbc);
        
        // Remediation
        gbc.gridx = 0; gbc.gridy = 3;
        gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        fieldsPanel.add(new JLabel("Remediation:"), gbc);
        
        gbc.gridx = 1; gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        remediationArea = new JTextArea(3, 40);
        remediationArea.setLineWrap(true);
        remediationArea.setWrapStyleWord(true);
        JScrollPane remScroll = new JScrollPane(remediationArea);
        remScroll.setPreferredSize(new Dimension(400, 60));
        fieldsPanel.add(remScroll, gbc);
        
        fieldsPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, fieldsPanel.getPreferredSize().height));
        panel.add(fieldsPanel);
        
        // Add spacing
        panel.add(Box.createVerticalStrut(15));
        
        // CVSS Panel
        JPanel cvssPanel = createCvssPanel();
        cvssPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(cvssPanel);
        
        return panel;
    }
    
    /**
     * CVSS scoring panel with mode toggle and manual metrics.
     */
    private JPanel createCvssPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("CVSS v3.1 Scoring"));
        
        // Top controls - Mode selection
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        topPanel.add(new JLabel("Scoring Mode:"));
        
        cvssMode = new JComboBox<>(new String[]{
            "Manual (Use CVSS Calculator)",
            "Automatic (Select Severity)"
        });
        topPanel.add(cvssMode);
        
        topPanel.add(Box.createHorizontalStrut(20));
        topPanel.add(new JLabel("Severity:"));
        severityDropdown = new JComboBox<>(new String[]{"Critical", "High", "Medium", "Low"});
        severityDropdown.setSelectedIndex(0); // Default to Critical
        severityDropdown.setEnabled(false); // Disabled by default (manual mode)
        topPanel.add(severityDropdown);
        
        // Add listeners AFTER creating both components
        cvssMode.addActionListener(e -> {
            boolean isManual = cvssMode.getSelectedIndex() == 0;
            severityDropdown.setEnabled(!isManual);
            
            // Enable/disable buttons
            for (List<JButton> buttons : cvssButtons.values()) {
                for (JButton btn : buttons) {
                    btn.setEnabled(isManual);
                }
            }
            
            // Apply preset when switching to automatic
            if (!isManual) {
                applySeverityPreset((String) severityDropdown.getSelectedItem());
            }
        });
        
        severityDropdown.addActionListener(e -> {
            // Only apply preset in automatic mode
            if (cvssMode.getSelectedIndex() == 1) {
                applySeverityPreset((String) severityDropdown.getSelectedItem());
            }
        });
        
        panel.add(topPanel, BorderLayout.NORTH);
        
        // CVSS metrics panel with nice grid layout
        cvssManualPanel = new JPanel();
        cvssManualPanel.setLayout(new BoxLayout(cvssManualPanel, BoxLayout.Y_AXIS));
        cvssManualPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        
        // Score display row
        JPanel scorePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        scorePanel.add(new JLabel("Score:"));
        cvssScoreLabel = new JLabel("0.0 (None)");
        cvssScoreLabel.setFont(cvssScoreLabel.getFont().deriveFont(Font.BOLD, 14f));
        scorePanel.add(cvssScoreLabel);
        scorePanel.add(Box.createHorizontalStrut(15));
        scorePanel.add(new JLabel("Impact:"));
        impactLabel = new JLabel("0.0");
        scorePanel.add(impactLabel);
        scorePanel.add(Box.createHorizontalStrut(15));
        scorePanel.add(new JLabel("Exploitability:"));
        exploitabilityLabel = new JLabel("0.0");
        scorePanel.add(exploitabilityLabel);
        cvssManualPanel.add(scorePanel);
        cvssManualPanel.add(Box.createVerticalStrut(8));
        
        // Metrics in a cleaner grid
        JPanel metricsGrid = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        int row = 0;
        
        // Attack Vector
        addMetricRow(metricsGrid, gbc, row++, "Attack Vector:", "AV", 
            new String[]{"Network", "Adjacent", "Local", "Physical"},
            new String[]{"N", "A", "L", "P"});
        
        // Attack Complexity
        addMetricRow(metricsGrid, gbc, row++, "Attack Complexity:", "AC",
            new String[]{"Low", "High"},
            new String[]{"L", "H"});
        
        // Privileges Required
        addMetricRow(metricsGrid, gbc, row++, "Privileges Required:", "PR",
            new String[]{"None", "Low", "High"},
            new String[]{"N", "L", "H"});
        
        // User Interaction
        addMetricRow(metricsGrid, gbc, row++, "User Interaction:", "UI",
            new String[]{"None", "Required"},
            new String[]{"N", "R"});
        
        // Scope
        addMetricRow(metricsGrid, gbc, row++, "Scope:", "S",
            new String[]{"Unchanged", "Changed"},
            new String[]{"U", "C"});
        
        // Confidentiality
        addMetricRow(metricsGrid, gbc, row++, "Confidentiality:", "C",
            new String[]{"None", "Low", "High"},
            new String[]{"N", "L", "H"});
        
        // Integrity
        addMetricRow(metricsGrid, gbc, row++, "Integrity:", "I",
            new String[]{"None", "Low", "High"},
            new String[]{"N", "L", "H"});
        
        // Availability
        addMetricRow(metricsGrid, gbc, row++, "Availability:", "A",
            new String[]{"None", "Low", "High"},
            new String[]{"N", "L", "H"});
        
        cvssManualPanel.add(metricsGrid);
        
        panel.add(cvssManualPanel, BorderLayout.CENTER);
        
        // Initialize default CVSS metrics
        initializeCvssDefaults();
        
        return panel;
    }
    
    // Flag to prevent feedback loops during button updates
    private boolean updatingCvssButtons = false;
    
    private void addMetricRow(JPanel grid, GridBagConstraints gbc, int row, 
                              String label, String key, String[] displayValues, String[] metricValues) {
        // Label
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        JLabel lbl = new JLabel(label);
        lbl.setPreferredSize(new Dimension(130, 25));
        grid.add(lbl, gbc);
        
        // Buttons panel
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        
        List<JButton> buttons = new ArrayList<>();
        
        for (int i = 0; i < displayValues.length; i++) {
            JButton btn = new JButton(displayValues[i]);
            // Set BasicButtonUI once at creation to ensure colors work
            btn.setUI(new javax.swing.plaf.basic.BasicButtonUI());
            btn.setFocusPainted(false);
            btn.setContentAreaFilled(true);
            btn.setOpaque(true);
            btn.putClientProperty("cvssKey", key);
            btn.putClientProperty("cvssValue", metricValues[i]);
            
            final String metricKey = key;
            final String metricValue = metricValues[i];
            
            btn.addActionListener(e -> {
                if (updatingCvssButtons) return;
                if (!btn.isEnabled()) return;
                
                // Log the click
                logging.logToOutput("CVSS Button clicked: " + metricKey + " = " + metricValue);
                
                // Update the metric and refresh
                cvssMetrics.put(metricKey, metricValue);
                updateAllButtonStyles();
                updateCvssScore();
            });
            
            buttonsPanel.add(btn);
            buttons.add(btn);
        }
        
        cvssButtons.put(key, buttons);
        grid.add(buttonsPanel, gbc);
    }
    
    private void updateAllButtonStyles() {
        updatingCvssButtons = true;
        try {
            logging.logToOutput("Updating button styles. Current metrics:");
            for (String key : cvssButtons.keySet()) {
                String currentValue = cvssMetrics.get(key);
                logging.logToOutput("  " + key + " = " + currentValue);
                List<JButton> buttons = cvssButtons.get(key);
                if (buttons == null) continue;
                
                for (JButton btn : buttons) {
                    String btnValue = (String) btn.getClientProperty("cvssValue");
                    boolean isSelected = btnValue != null && btnValue.equals(currentValue);
                    
                    if (isSelected) {
                        btn.setBackground(new Color(51, 122, 183));
                        btn.setForeground(Color.WHITE);
                        btn.setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createLineBorder(new Color(40, 96, 144), 1),
                            BorderFactory.createEmptyBorder(3, 7, 3, 7)
                        ));
                    } else {
                        btn.setBackground(Color.WHITE);
                        btn.setForeground(Color.DARK_GRAY);
                        btn.setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createLineBorder(new Color(180, 180, 180), 1),
                            BorderFactory.createEmptyBorder(3, 7, 3, 7)
                        ));
                    }
                    btn.repaint();
                }
            }
        } finally {
            updatingCvssButtons = false;
        }
    }
    
    private void initializeCvssDefaults() {
        // Set default values - Critical severity: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
        cvssMetrics.put("AV", "N");
        cvssMetrics.put("AC", "L");
        cvssMetrics.put("PR", "N");
        cvssMetrics.put("UI", "N");
        cvssMetrics.put("S", "U");
        cvssMetrics.put("C", "H");
        cvssMetrics.put("I", "H");
        cvssMetrics.put("A", "H");
        
        // Update all button styles and calculate score
        updateAllButtonStyles();
        updateCvssScore();
    }
    
    /**
     * Applies CVSS metric presets based on severity selection.
     * These are accurate CVSS 3.1 vectors verified against FIRST calculator.
     */
    private void applySeverityPreset(String severity) {
        if (severity == null) return;
        
        switch (severity) {
            case "Critical" -> {
                // CVSS 9.8 Critical - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                setMetricsPreset("N", "L", "N", "N", "U", "H", "H", "H");
            }
            case "High" -> {
                // CVSS 7.5 High - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
                setMetricsPreset("N", "L", "N", "N", "U", "H", "N", "N");
            }
            case "Medium" -> {
                // CVSS 5.3 Medium - AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
                setMetricsPreset("N", "L", "N", "N", "U", "L", "N", "N");
            }
            case "Low" -> {
                // CVSS 3.1 Low - AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N
                setMetricsPreset("N", "H", "L", "N", "U", "L", "N", "N");
            }
        }
        
        updateAllButtonStyles();
        updateCvssScore();
    }
    
    private void setMetricsPreset(String av, String ac, String pr, String ui, 
                                   String s, String c, String i, String a) {
        cvssMetrics.put("AV", av);
        cvssMetrics.put("AC", ac);
        cvssMetrics.put("PR", pr);
        cvssMetrics.put("UI", ui);
        cvssMetrics.put("S", s);
        cvssMetrics.put("C", c);
        cvssMetrics.put("I", i);
        cvssMetrics.put("A", a);
    }
    
    private void updateCvssScore() {
        String vector = buildCvssVector();
        CvssResult result = Cvss31Calculator.calculate(vector);
        
        // Log for debugging
        logging.logToOutput("CVSS Vector: " + vector + " => Score: " + result.baseScore + " (" + result.severity + ")");
        
        // Update display labels - include vector for debugging
        cvssScoreLabel.setText(String.format("%.1f (%s)", result.baseScore, result.severity));
        impactLabel.setText(String.format("%.1f", result.impactSubscore));
        exploitabilityLabel.setText(String.format("%.1f", result.exploitabilitySubscore));
        
        // Update score label color based on severity
        Color scoreColor = switch (result.severity) {
            case "Critical" -> new Color(139, 0, 0);
            case "High" -> new Color(220, 53, 69);
            case "Medium" -> new Color(255, 152, 0);
            case "Low" -> new Color(40, 167, 69);
            default -> Color.GRAY;
        };
        cvssScoreLabel.setForeground(scoreColor);
    }
    
    private String buildCvssVector() {
        return "CVSS:3.1" +
               "/AV:" + cvssMetrics.getOrDefault("AV", "N") +
               "/AC:" + cvssMetrics.getOrDefault("AC", "L") +
               "/PR:" + cvssMetrics.getOrDefault("PR", "N") +
               "/UI:" + cvssMetrics.getOrDefault("UI", "N") +
               "/S:" + cvssMetrics.getOrDefault("S", "U") +
               "/C:" + cvssMetrics.getOrDefault("C", "N") +
               "/I:" + cvssMetrics.getOrDefault("I", "N") +
               "/A:" + cvssMetrics.getOrDefault("A", "N");
    }
    
    // File upload methods
    private void selectFilesToUpload() {
        JFileChooser chooser = new JFileChooser();
        chooser.setMultiSelectionEnabled(true);
        chooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            @Override
            public boolean accept(File f) {
                if (f.isDirectory()) return true;
                String name = f.getName().toLowerCase();
                return name.endsWith(".png") || name.endsWith(".jpg") || name.endsWith(".jpeg") ||
                       name.endsWith(".gif") || name.endsWith(".webp") || name.endsWith(".bmp") ||
                       name.endsWith(".txt") || name.endsWith(".log") || name.endsWith(".pdf");
            }
            @Override
            public String getDescription() {
                return "Image and Text files";
            }
        });
        
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File[] files = chooser.getSelectedFiles();
            for (File file : files) {
                // Avoid duplicates
                boolean exists = false;
                for (int i = 0; i < proofsListModel.size(); i++) {
                    if (proofsListModel.get(i).name.equals(file.getName())) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    uploadQueue.add(file);
                    proofsListModel.addElement(new FileEntry(file.getName(), file.length(), FileStatus.PENDING, null));
                }
            }
        }
    }
    
    private void removeSelectedProof() {
        int index = proofsList.getSelectedIndex();
        if (index >= 0) {
            FileEntry entry = proofsListModel.get(index);
            // Remove from upload queue
            uploadQueue.removeIf(f -> f.getName().equals(entry.name));
            proofsListModel.remove(index);
        }
    }
    
    private void clearAllProofs() {
        uploadQueue.clear();
        proofsListModel.clear();
    }
    
    /**
     * Upload all pending proofs to PwnDoc.
     * This should be called BEFORE creating the finding.
     * 
     * @param auditId The audit ID to upload images to
     * @param callback Callback with (success, list of image IDs)
     */
    public void uploadPendingProofs(String auditId, BiConsumer<Boolean, List<String>> callback) {
        if (uploadQueue.isEmpty()) {
            callback.accept(true, new ArrayList<>());
            return;
        }
        
        List<String> uploadedImageIds = Collections.synchronizedList(new ArrayList<>());
        List<String> failedFiles = Collections.synchronizedList(new ArrayList<>());
        
        SwingWorker<Void, FileUploadProgress> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                for (File file : uploadQueue) {
                    // Update status to uploading
                    publish(new FileUploadProgress(file.getName(), FileStatus.UPLOADING, null));
                    
                    try {
                        // Read file and encode as base64
                        byte[] fileBytes = Files.readAllBytes(file.toPath());
                        String base64 = Base64.getEncoder().encodeToString(fileBytes);
                        
                        // Determine MIME type prefix for data URL
                        String mimeType = getMimeType(file.getName());
                        String dataUrl = "data:" + mimeType + ";base64," + base64;
                        
                        // Upload to PwnDoc
                        ApiResult<JsonObject> result = apiClient.uploadImage(auditId, file.getName(), dataUrl);
                        
                        if (result.isSuccess()) {
                            JsonObject response = result.getData();
                            String imageId = null;
                            if (response.has("datas") && response.get("datas").isJsonObject()) {
                                JsonObject datas = response.getAsJsonObject("datas");
                                if (datas.has("_id")) {
                                    imageId = datas.get("_id").getAsString();
                                }
                            }
                            if (imageId != null) {
                                uploadedImageIds.add(imageId);
                            }
                            publish(new FileUploadProgress(file.getName(), FileStatus.UPLOADED, null));
                            logging.logToOutput("Uploaded image: " + file.getName() + " -> " + imageId);
                        } else {
                            failedFiles.add(file.getName());
                            publish(new FileUploadProgress(file.getName(), FileStatus.FAILED, result.getError()));
                            logging.logToError("Failed to upload " + file.getName() + ": " + result.getError());
                        }
                    } catch (IOException e) {
                        failedFiles.add(file.getName());
                        publish(new FileUploadProgress(file.getName(), FileStatus.FAILED, e.getMessage()));
                        logging.logToError("Error uploading " + file.getName() + ": " + e.getMessage());
                    }
                }
                return null;
            }
            
            @Override
            protected void process(List<FileUploadProgress> chunks) {
                for (FileUploadProgress progress : chunks) {
                    // Update UI status for each file
                    for (int i = 0; i < proofsListModel.size(); i++) {
                        FileEntry entry = proofsListModel.get(i);
                        if (entry.name.equals(progress.fileName)) {
                            proofsListModel.set(i, new FileEntry(entry.name, entry.size, progress.status, progress.error));
                            break;
                        }
                    }
                }
            }
            
            @Override
            protected void done() {
                // Clear successfully uploaded files from queue
                uploadQueue.removeIf(f -> !failedFiles.contains(f.getName()));
                
                boolean allSuccess = failedFiles.isEmpty();
                callback.accept(allSuccess, new ArrayList<>(uploadedImageIds));
            }
        };
        worker.execute();
    }
    
    private String getMimeType(String fileName) {
        String lower = fileName.toLowerCase();
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".gif")) return "image/gif";
        if (lower.endsWith(".webp")) return "image/webp";
        if (lower.endsWith(".bmp")) return "image/bmp";
        if (lower.endsWith(".pdf")) return "application/pdf";
        if (lower.endsWith(".txt") || lower.endsWith(".log")) return "text/plain";
        return "application/octet-stream";
    }
    
    // Custom fields loading and building
    private void loadCustomFields() {
        SwingWorker<List<CustomField>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<CustomField> doInBackground() {
                var result = apiClient.getCustomFields();
                return result.isSuccess() ? result.getData() : new ArrayList<>();
            }
            
            @Override
            protected void done() {
                try {
                    allCustomFields = get();
                    logging.logToOutput("Loaded " + allCustomFields.size() + " total custom fields");
                    
                    // Only build panel if audit type is already set
                    // Otherwise, setAuditType() will trigger the build later
                    if (currentDisplaySub != null && !currentDisplaySub.isEmpty()) {
                        buildCustomFieldsPanel();
                    } else {
                        // Show waiting message
                        customFieldsPanel.removeAll();
                        JLabel waitLabel = new JLabel("Select an audit to see custom fields");
                        waitLabel.setForeground(Color.GRAY);
                        customFieldsPanel.add(waitLabel);
                        customFieldsPanel.revalidate();
                        customFieldsPanel.repaint();
                    }
                } catch (Exception e) {
                    logging.logToError("Error loading custom fields: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    /**
     * Build custom fields panel with DYNAMIC filtering based on audit type.
     * 
     * Filtering logic (fully agnostic to PwnDoc configuration):
     * 1. Field must have display="vulnerability" (findings are vulnerability-related)
     * 2. If audit type is set, filter by displaySub matching the mapped audit type
     * 3. If displaySub is empty, the field applies to ALL audit types
     * 4. Avoid duplicates by label (case-insensitive)
     */
    private void buildCustomFieldsPanel() {
        customFieldsPanel.removeAll();
        customFieldComponents.clear();
        customFieldTypes.clear();
        customFieldIds.clear();
        
        // Track added field labels to avoid duplicates
        Set<String> addedLabels = new HashSet<>();
        
        // Filter custom fields dynamically
        List<CustomField> fieldsToShow = new ArrayList<>();
        
        for (CustomField field : allCustomFields) {
            // Skip fields with empty label or space type
            if (field.label == null || field.label.trim().isEmpty()) {
                continue;
            }
            if ("space".equalsIgnoreCase(field.fieldType)) {
                continue;
            }
            
            // Only include vulnerability/finding display fields
            String displayValue = field.display != null ? field.display.toLowerCase().trim() : "";
            boolean isVulnerabilityField = "vulnerability".equals(displayValue) || "finding".equals(displayValue);
            
            if (!isVulnerabilityField) {
                continue;
            }
            
            // Filter by displaySub if audit type is set
            if (currentDisplaySub != null && !currentDisplaySub.isEmpty()) {
                String fieldDisplaySub = field.displaySub != null ? field.displaySub.trim() : "";
                
                // Include field if:
                // 1. displaySub is empty (universal field), OR
                // 2. displaySub matches current audit type
                boolean matchesAuditType = fieldDisplaySub.isEmpty() || 
                                           fieldDisplaySub.equalsIgnoreCase(currentDisplaySub);
                
                if (!matchesAuditType) {
                    continue;
                }
            }
            
            // Avoid duplicates by label (case-insensitive)
            String labelKey = field.label.toLowerCase().trim();
            if (!addedLabels.contains(labelKey)) {
                fieldsToShow.add(field);
                addedLabels.add(labelKey);
            }
        }
        
        logging.logToOutput("Showing " + fieldsToShow.size() + " custom fields for audit type: " + 
                          currentAuditType + " (displaySub=" + currentDisplaySub + ")");
        
        if (fieldsToShow.isEmpty()) {
            JLabel noFieldsLabel = new JLabel("No custom fields defined for this audit type");
            noFieldsLabel.setForeground(Color.GRAY);
            noFieldsLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
            customFieldsPanel.add(noFieldsLabel);
        } else {
            // Create a grid layout for compact fields
            JPanel gridPanel = new JPanel(new GridBagLayout());
            gridPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(5, 5, 5, 5);
            gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            
            int col = 0;
            int row = 0;
            int maxCols = 3;
            
            for (CustomField field : fieldsToShow) {
                JPanel fieldPanel = createCustomFieldPanel(field);
                if (fieldPanel == null) continue;
                
                boolean isLargeField = "textarea".equalsIgnoreCase(field.fieldType) ||
                                       "text".equalsIgnoreCase(field.fieldType);
                
                if (isLargeField) {
                    // Full width for textarea fields
                    if (col > 0) {
                        row++;
                        col = 0;
                    }
                    gbc.gridx = 0;
                    gbc.gridy = row;
                    gbc.gridwidth = maxCols;
                    gbc.weightx = 1.0;
                    gbc.fill = GridBagConstraints.BOTH;
                    gridPanel.add(fieldPanel, gbc);
                    row++;
                    gbc.gridwidth = 1;
                    gbc.fill = GridBagConstraints.HORIZONTAL;
                } else {
                    // Regular field in column layout
                    gbc.gridx = col;
                    gbc.gridy = row;
                    gbc.weightx = 1.0 / maxCols;
                    gridPanel.add(fieldPanel, gbc);
                    
                    col++;
                    if (col >= maxCols) {
                        col = 0;
                        row++;
                    }
                }
            }
            
            customFieldsPanel.add(gridPanel);
        }
        
        customFieldsPanel.revalidate();
        customFieldsPanel.repaint();
    }
    
    private JPanel createCustomFieldPanel(CustomField field) {
        JPanel panel = new JPanel(new BorderLayout(5, 3));
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(200, 200, 200), 1, true),
            BorderFactory.createEmptyBorder(5, 8, 5, 8)
        ));
        panel.setBackground(Color.WHITE);
        
        // Label
        String labelText = field.label + (field.required ? " *" : "");
        JLabel label = new JLabel(labelText);
        label.setFont(label.getFont().deriveFont(Font.PLAIN, 11f));
        label.setForeground(Color.DARK_GRAY);
        panel.add(label, BorderLayout.NORTH);
        
        // Create component based on field type
        JComponent component = createFieldComponent(field);
        if (component == null) return null;
        
        panel.add(component, BorderLayout.CENTER);
        
        // Store reference for later retrieval
        customFieldComponents.put(field.label, component);
        customFieldTypes.put(field.label, field.fieldType);
        // Store the ID for API calls
        if (field.id != null) {
            customFieldIds.put(field.label, field.id);
        }
        
        return panel;
    }
    
    private JComponent createFieldComponent(CustomField field) {
        String type = field.fieldType != null ? field.fieldType.toLowerCase() : "input";
        
        switch (type) {
            case "input":
            case "text-input":
                JTextField textField = new JTextField(20);
                return textField;
                
            case "textarea":
            case "text":
            case "text-area":
                JTextArea textArea = new JTextArea(3, 20);
                textArea.setLineWrap(true);
                textArea.setWrapStyleWord(true);
                JScrollPane scroll = new JScrollPane(textArea);
                scroll.setPreferredSize(new Dimension(300, 60));
                return scroll;
                
            case "select":
            case "dropdown":
                JComboBox<String> combo = new JComboBox<>();
                combo.addItem(""); // Empty option
                // field.options is List<String>
                if (field.options != null) {
                    Set<String> addedOptions = new HashSet<>();
                    for (String opt : field.options) {
                        if (opt != null && !opt.isEmpty() && !addedOptions.contains(opt)) {
                            combo.addItem(opt);
                            addedOptions.add(opt);
                        }
                    }
                }
                return combo;
                
            case "select-multiple":
            case "multi-select":
                DefaultListModel<String> listModel = new DefaultListModel<>();
                // field.options is List<String>
                if (field.options != null) {
                    Set<String> addedOptions = new HashSet<>();
                    for (String opt : field.options) {
                        if (opt != null && !opt.isEmpty() && !addedOptions.contains(opt)) {
                            listModel.addElement(opt);
                            addedOptions.add(opt);
                        }
                    }
                }
                JList<String> list = new JList<>(listModel);
                list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
                list.setVisibleRowCount(3);
                JScrollPane listScroll = new JScrollPane(list);
                listScroll.setPreferredSize(new Dimension(200, 60));
                return listScroll;
                
            case "checkbox":
                JCheckBox checkBox = new JCheckBox();
                return checkBox;
                
            case "date":
                JTextField dateField = new JTextField(10);
                dateField.setToolTipText("Format: YYYY-MM-DD");
                return dateField;
                
            case "number":
                JSpinner spinner = new JSpinner(new SpinnerNumberModel(0, 0, 10000, 1));
                return spinner;
                
            default:
                JTextField defaultField = new JTextField(20);
                return defaultField;
        }
    }
    
    // Populate editor from a vulnerability template
    public void populateFromTemplate(JsonObject vulnerability) {
        logging.logToOutput("=== populateFromTemplate called ===");
        
        this.currentVulnerability = vulnerability;
        this.currentFindingId = null;
        this.existingPoc = null;  // Clear for new finding
        
        // Clear proofs for new finding
        clearAllProofs();
        
        // Populate fields from template - detail can be array OR object
        if (vulnerability.has("detail")) {
            JsonElement detailElement = vulnerability.get("detail");
            
            if (detailElement.isJsonArray()) {
                // Multiple locales - find English
                JsonArray details = detailElement.getAsJsonArray();
                logging.logToOutput("Detail is array with " + details.size() + " entries");
                for (JsonElement el : details) {
                    if (el.isJsonObject()) {
                        JsonObject detail = el.getAsJsonObject();
                        String locale = getJsonString(detail, "locale");
                        if ("en".equalsIgnoreCase(locale) || "En".equalsIgnoreCase(locale)) {
                            populateFieldsFromDetail(detail);
                            break;
                        }
                    }
                }
            } else if (detailElement.isJsonObject()) {
                // Single locale - use directly
                JsonObject detail = detailElement.getAsJsonObject();
                logging.logToOutput("Detail is object, locale: " + getJsonString(detail, "locale"));
                populateFieldsFromDetail(detail);
            }
        } else {
            logging.logToOutput("No 'detail' field found in vulnerability");
        }
        
        // Set type
        if (vulnerability.has("category")) {
            String category = getJsonString(vulnerability, "category");
            for (int i = 0; i < typeCombo.getItemCount(); i++) {
                if (typeCombo.getItemAt(i).equals(category)) {
                    typeCombo.setSelectedIndex(i);
                    break;
                }
            }
        }
        
        // Set CVSS
        if (vulnerability.has("cvssv3")) {
            String cvss = getJsonString(vulnerability, "cvssv3");
            if (cvss != null && !cvss.isEmpty()) {
                updateMetricsFromVector(cvss);
            }
        }
        
        // Set priority
        if (vulnerability.has("priority")) {
            int priority = vulnerability.get("priority").getAsInt();
            if (priority >= 1 && priority <= 4) {
                priorityCombo.setSelectedIndex(priority - 1);
            }
        }
        
        // Populate custom fields if present
        if (vulnerability.has("customFields")) {
            populateCustomFieldsFromJson(vulnerability.get("customFields"));
        }
    }
    
    /**
     * Helper to populate text fields from a detail object
     */
    private void populateFieldsFromDetail(JsonObject detail) {
        String title = stripHtml(getJsonString(detail, "title"));
        logging.logToOutput("Setting title: " + title);
        titleField.setText(title);
        descriptionArea.setText(stripHtml(getJsonString(detail, "description")));
        observationArea.setText(stripHtml(getJsonString(detail, "observation")));
        remediationArea.setText(stripHtml(getJsonString(detail, "remediation")));
        
        // References
        if (detail.has("references") && detail.get("references").isJsonArray()) {
            StringBuilder refs = new StringBuilder();
            for (JsonElement ref : detail.getAsJsonArray("references")) {
                if (refs.length() > 0) refs.append("\n");
                refs.append(ref.getAsString());
            }
            referencesArea.setText(refs.toString());
        }
    }
    
    // Populate editor from an existing finding (for update)
    public void populateFromFinding(JsonObject finding) {
        this.currentFindingId = getJsonString(finding, "_id");
        
        // Store existing poc content to preserve it
        this.existingPoc = getJsonString(finding, "poc");
        
        // Clear proofs
        clearAllProofs();
        
        // Populate standard fields
        titleField.setText(stripHtml(getJsonString(finding, "title")));
        descriptionArea.setText(stripHtml(getJsonString(finding, "description")));
        observationArea.setText(stripHtml(getJsonString(finding, "observation")));
        remediationArea.setText(stripHtml(getJsonString(finding, "remediation")));
        
        // Scope/affected assets
        if (finding.has("scope")) {
            affectedAssetsArea.setText(getJsonString(finding, "scope"));
        }
        
        // Type/category
        String category = getJsonString(finding, "category");
        if (category != null) {
            for (int i = 0; i < typeCombo.getItemCount(); i++) {
                if (typeCombo.getItemAt(i).equals(category)) {
                    typeCombo.setSelectedIndex(i);
                    break;
                }
            }
        }
        
        // CVSS
        String cvss = getJsonString(finding, "cvssv3");
        if (cvss != null && !cvss.isEmpty()) {
            updateMetricsFromVector(cvss);
        }
        
        // Priority
        if (finding.has("priority")) {
            int priority = finding.get("priority").getAsInt();
            if (priority >= 1 && priority <= 4) {
                priorityCombo.setSelectedIndex(priority - 1);
            }
        }
        
        // Remediation difficulty
        if (finding.has("remediationComplexity")) {
            int complexity = finding.get("remediationComplexity").getAsInt();
            if (complexity >= 1 && complexity <= 3) {
                remediationDifficultyCombo.setSelectedIndex(complexity - 1);
            }
        }
        
        // References
        if (finding.has("references") && finding.get("references").isJsonArray()) {
            StringBuilder refs = new StringBuilder();
            for (JsonElement ref : finding.getAsJsonArray("references")) {
                if (refs.length() > 0) refs.append("\n");
                refs.append(ref.isJsonObject() ? getJsonString(ref.getAsJsonObject(), "value") : ref.getAsString());
            }
            referencesArea.setText(refs.toString());
        }
        
        // Custom fields
        if (finding.has("customFields")) {
            populateCustomFieldsFromJson(finding.get("customFields"));
        }
    }
    
    private void populateCustomFieldsFromJson(JsonElement customFieldsElement) {
        if (customFieldsElement == null) return;
        
        // Build reverse lookup map: ID -> label
        Map<String, String> idToLabel = new HashMap<>();
        for (Map.Entry<String, String> entry : customFieldIds.entrySet()) {
            idToLabel.put(entry.getValue(), entry.getKey());
        }
        
        // Custom fields can be an array or object
        if (customFieldsElement.isJsonArray()) {
            JsonArray arr = customFieldsElement.getAsJsonArray();
            for (JsonElement el : arr) {
                if (el.isJsonObject()) {
                    JsonObject cf = el.getAsJsonObject();
                    
                    // Try multiple ways to find the matching component
                    String label = getJsonString(cf, "label");
                    String customFieldId = getJsonString(cf, "customField");
                    String id = getJsonString(cf, "_id");
                    
                    // Find matching label
                    String matchedLabel = null;
                    if (label != null && customFieldComponents.containsKey(label)) {
                        matchedLabel = label;
                    } else if (customFieldId != null && idToLabel.containsKey(customFieldId)) {
                        matchedLabel = idToLabel.get(customFieldId);
                    } else if (id != null && idToLabel.containsKey(id)) {
                        matchedLabel = idToLabel.get(id);
                    }
                    
                    if (matchedLabel != null && customFieldComponents.containsKey(matchedLabel)) {
                        JsonElement value = cf.get("text");
                        if (value == null) value = cf.get("value");
                        setComponentValue(customFieldComponents.get(matchedLabel), value);
                    }
                }
            }
        } else if (customFieldsElement.isJsonObject()) {
            JsonObject obj = customFieldsElement.getAsJsonObject();
            for (String key : obj.keySet()) {
                String matchedLabel = key;
                // If key is an ID, try to find the label
                if (!customFieldComponents.containsKey(key) && idToLabel.containsKey(key)) {
                    matchedLabel = idToLabel.get(key);
                }
                if (customFieldComponents.containsKey(matchedLabel)) {
                    setComponentValue(customFieldComponents.get(matchedLabel), obj.get(key));
                }
            }
        }
    }
    
    @SuppressWarnings("unchecked")
    private void setComponentValue(JComponent component, JsonElement value) {
        if (value == null || value.isJsonNull()) return;
        
        if (component instanceof JTextField) {
            ((JTextField) component).setText(value.isJsonPrimitive() ? value.getAsString() : "");
        } else if (component instanceof JScrollPane) {
            Component view = ((JScrollPane) component).getViewport().getView();
            if (view instanceof JTextArea) {
                ((JTextArea) view).setText(value.isJsonPrimitive() ? value.getAsString() : "");
            } else if (view instanceof JList) {
                // Multi-select
                if (value.isJsonArray()) {
                    JList<String> list = (JList<String>) view;
                    List<Integer> indices = new ArrayList<>();
                    ListModel<String> model = list.getModel();
                    for (JsonElement el : value.getAsJsonArray()) {
                        String val = el.getAsString();
                        for (int i = 0; i < model.getSize(); i++) {
                            if (model.getElementAt(i).equals(val)) {
                                indices.add(i);
                                break;
                            }
                        }
                    }
                    int[] arr = indices.stream().mapToInt(i -> i).toArray();
                    list.setSelectedIndices(arr);
                }
            }
        } else if (component instanceof JComboBox) {
            String val = value.isJsonPrimitive() ? value.getAsString() : "";
            ((JComboBox<String>) component).setSelectedItem(val);
        } else if (component instanceof JCheckBox) {
            boolean checked = value.isJsonPrimitive() && value.getAsBoolean();
            ((JCheckBox) component).setSelected(checked);
        } else if (component instanceof JSpinner) {
            if (value.isJsonPrimitive()) {
                try {
                    ((JSpinner) component).setValue(value.getAsInt());
                } catch (Exception e) {
                    // Ignore
                }
            }
        }
    }
    
    private void updateMetricsFromVector(String vector) {
        if (vector == null || !vector.contains("CVSS:3")) return;
        
        logging.logToOutput("Parsing CVSS vector from template: " + vector);
        
        // Parse vector string
        String[] parts = vector.split("/");
        for (String part : parts) {
            if (part.contains(":")) {
                String[] kv = part.split(":");
                if (kv.length == 2) {
                    String key = kv[0];
                    String value = kv[1];
                    
                    if (cvssButtons.containsKey(key)) {
                        cvssMetrics.put(key, value);
                        logging.logToOutput("  Set " + key + " = " + value);
                    }
                }
            }
        }
        
        // Update all button visuals to match the metrics
        updateAllButtonStyles();
        updateCvssScore();
    }
    
    // Build finding JSON for API
    @SuppressWarnings("unchecked")
    public JsonObject getFindingData() {
        JsonObject finding = new JsonObject();
        
        finding.addProperty("title", titleField.getText().trim());
        finding.addProperty("vulnType", typeCombo.getSelectedItem().toString());
        finding.addProperty("description", descriptionArea.getText().trim());
        finding.addProperty("observation", observationArea.getText().trim());
        finding.addProperty("remediation", remediationArea.getText().trim());
        finding.addProperty("scope", affectedAssetsArea.getText().trim());
        
        // Category - must match vulnType
        finding.addProperty("category", typeCombo.getSelectedItem().toString());
        
        // Priority (1-4)
        finding.addProperty("priority", priorityCombo.getSelectedIndex() + 1);
        
        // Remediation complexity (1-3)
        finding.addProperty("remediationComplexity", remediationDifficultyCombo.getSelectedIndex() + 1);
        
        // CVSS - only send the vector, let PwnDoc compute severity
        finding.addProperty("cvssv3", buildCvssVector());
        
        // NOTE: Do NOT send "severity" - PwnDoc computes this from cvssv3
        // Sending it can cause issues with the API
        
        // References as array
        JsonArray refs = new JsonArray();
        String refText = referencesArea.getText().trim();
        if (!refText.isEmpty()) {
            for (String line : refText.split("\n")) {
                if (!line.trim().isEmpty()) {
                    refs.add(line.trim());
                }
            }
        }
        finding.add("references", refs);
        
        // Custom fields - use ID if available, otherwise use label
        JsonArray customFields = new JsonArray();
        for (Map.Entry<String, JComponent> entry : customFieldComponents.entrySet()) {
            String label = entry.getKey();
            JComponent component = entry.getValue();
            
            // Get the value first - skip empty values
            Object value = getComponentValue(component);
            if (value == null) continue;
            if (value instanceof String && ((String) value).isEmpty()) continue;
            if (value instanceof List && ((List<?>) value).isEmpty()) continue;
            
            JsonObject cf = new JsonObject();
            // Use the ID if available, otherwise use label
            String fieldId = customFieldIds.get(label);
            cf.addProperty("customField", fieldId != null ? fieldId : label);
            
            if (value instanceof String) {
                cf.addProperty("text", (String) value);
            } else if (value instanceof Boolean) {
                cf.addProperty("text", (Boolean) value);
            } else if (value instanceof Number) {
                cf.addProperty("text", (Number) value);
            } else if (value instanceof List) {
                JsonArray arr = new JsonArray();
                for (Object item : (List<?>) value) {
                    arr.add(item.toString());
                }
                cf.add("text", arr);
            }
            
            customFields.add(cf);
        }
        finding.add("customFields", customFields);
        
        return finding;
    }
    
    @SuppressWarnings("unchecked")
    private Object getComponentValue(JComponent component) {
        if (component instanceof JTextField) {
            return ((JTextField) component).getText().trim();
        } else if (component instanceof JScrollPane) {
            Component view = ((JScrollPane) component).getViewport().getView();
            if (view instanceof JTextArea) {
                return ((JTextArea) view).getText().trim();
            } else if (view instanceof JList) {
                JList<String> list = (JList<String>) view;
                return list.getSelectedValuesList();
            }
        } else if (component instanceof JComboBox) {
            Object selected = ((JComboBox<?>) component).getSelectedItem();
            return selected != null ? selected.toString() : "";
        } else if (component instanceof JCheckBox) {
            return ((JCheckBox) component).isSelected();
        } else if (component instanceof JSpinner) {
            return ((JSpinner) component).getValue();
        }
        return "";
    }
    
    public void setCurrentFindingId(String id) {
        this.currentFindingId = id;
    }
    
    public String getCurrentFindingId() {
        return currentFindingId;
    }
    
    public String getExistingPoc() {
        return existingPoc;
    }
    
    public boolean hasProofsToUpload() {
        return !uploadQueue.isEmpty();
    }
    
    // Helper methods
    private String getJsonString(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) {
            return "";
        }
        return obj.get(key).getAsString();
    }
    
    private String stripHtml(String text) {
        if (text == null) return "";
        return text.replaceAll("<[^>]*>", "").trim();
    }
    
    private String[] getVulnerabilityTypes() {
        // Load from API or use defaults
        try {
            // getVulnerabilityCategories returns ApiResult<List<String>>
            var result = apiClient.getVulnerabilityCategories();
            if (result.isSuccess() && result.getData() != null) {
                List<String> types = result.getData();
                if (!types.isEmpty()) {
                    return types.toArray(new String[0]);
                }
            }
        } catch (Exception e) {
            logging.logToError("Failed to load vulnerability categories: " + e.getMessage());
        }
        
        // Fallback defaults
        return new String[]{
            "Web Vulnerability",
            "Network Vulnerability", 
            "Mobile Vulnerability",
            "API Vulnerability",
            "Configuration Issue",
            "Authentication Issue",
            "Authorization Issue",
            "Injection",
            "Information Disclosure",
            "Other"
        };
    }
    
    // File entry classes for proofs list
    public enum FileStatus {
        PENDING, UPLOADING, UPLOADED, FAILED
    }
    
    public static class FileEntry {
        public final String name;
        public final long size;
        public final FileStatus status;
        public final String error;
        
        public FileEntry(String name, long size, FileStatus status, String error) {
            this.name = name;
            this.size = size;
            this.status = status;
            this.error = error;
        }
        
        @Override
        public String toString() {
            String sizeStr = size < 1024 ? size + " B" : 
                            size < 1024 * 1024 ? (size / 1024) + " KB" :
                            (size / (1024 * 1024)) + " MB";
            String statusStr = switch (status) {
                case PENDING -> "(pending)";
                case UPLOADING -> "(uploading...)";
                case UPLOADED -> "✓";
                case FAILED -> "✗ " + (error != null ? error : "failed");
            };
            return name + " [" + sizeStr + "] " + statusStr;
        }
    }
    
    private static class FileEntryRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            
            if (value instanceof FileEntry) {
                FileEntry entry = (FileEntry) value;
                switch (entry.status) {
                    case UPLOADED -> setForeground(new Color(40, 167, 69));
                    case FAILED -> setForeground(new Color(220, 53, 69));
                    case UPLOADING -> setForeground(new Color(255, 152, 0));
                    default -> setForeground(Color.BLACK);
                }
            }
            
            return this;
        }
    }
    
    private static class FileUploadProgress {
        final String fileName;
        final FileStatus status;
        final String error;
        
        FileUploadProgress(String fileName, FileStatus status, String error) {
            this.fileName = fileName;
            this.status = status;
            this.error = error;
        }
    }
}
