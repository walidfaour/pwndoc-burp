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
import com.walidfaour.pwndoc.api.PwnDocApiClient.Audit;
import com.walidfaour.pwndoc.config.ConfigManager;
import com.walidfaour.pwndoc.ui.components.SectionHeader;
import com.walidfaour.pwndoc.ui.components.StatusBanner;
import com.walidfaour.pwndoc.util.TokenManager;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Main window for Finding workflows (Create, Update, Delete).
 * Handles audit selection and delegates to appropriate sub-panels.
 * 
 * FIXES:
 * - Single scroll pane for entire workflow content (no nested scrolling)
 * - Passes audit type to FindingEditorPanel for custom field filtering
 */
public class FindingWorkflowWindow extends JFrame {
    
    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final PwnDocApiClient apiClient;
    private final TokenManager tokenManager;
    private final Logging logging;
    private final String mode; // "create", "update", "delete"
    private final String findingId;
    private final PwnDocContextMenuProvider.RequestContext requestContext;
    
    // UI Components
    private JPanel auditSelectorPanel;
    private JTable auditsTable;
    private DefaultTableModel auditsTableModel;
    private JButton makeDefaultButton;
    private JLabel currentAuditLabel;
    private StatusBanner auditStatusBanner;
    
    private JPanel workflowPanel;
    private FindingLibraryPanel libraryPanel;
    private FindingEditorPanel editorPanel;
    private StatusBanner mainStatusBanner;
    
    private String selectedAuditId;
    private String selectedAuditName;
    private String selectedAuditType; // Track audit type for custom field filtering
    
    // Cache for findings data
    private static final ConcurrentHashMap<String, CachedFindings> findingsCache = new ConcurrentHashMap<>();
    private static final long CACHE_TTL_MS = 30000; // 30 seconds cache TTL
    
    // Store findings data for reference (for update/delete operations)
    private JsonArray loadedFindings;
    
    // Reference to update panel components for Edit Selected wiring
    private JTable updateFindingsTable;
    private DefaultTableModel updateFindingsModel;
    
    public FindingWorkflowWindow(MontoyaApi api, ConfigManager configManager,
                                  PwnDocApiClient apiClient, TokenManager tokenManager,
                                  Logging logging, String mode, String findingId,
                                  PwnDocContextMenuProvider.RequestContext requestContext,
                                  boolean needsAuditSelection) {
        super(getWindowTitle(mode));
        this.api = api;
        this.configManager = configManager;
        this.apiClient = apiClient;
        this.tokenManager = tokenManager;
        this.logging = logging;
        this.mode = mode;
        this.findingId = findingId;
        this.requestContext = requestContext;
        
        initializeUI(needsAuditSelection);
        
        if (needsAuditSelection) {
            loadAudits();
        } else {
            // Use default audit
            selectedAuditId = configManager.getDefaultAuditId();
            selectedAuditName = configManager.getDefaultAuditName();
            selectedAuditType = configManager.getDefaultAuditType();
            
            // If we have audit ID but no type, fetch it from API
            if (selectedAuditId != null && !selectedAuditId.isEmpty() && 
                (selectedAuditType == null || selectedAuditType.isEmpty())) {
                fetchAuditType(selectedAuditId);
            }
            
            showWorkflowPanel();
        }
    }
    
    /**
     * Fetches the audit type from the API and updates the editor panel.
     * Called when we have an audit ID but the type wasn't saved.
     */
    private void fetchAuditType(String auditId) {
        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override
            protected String doInBackground() {
                var result = apiClient.getAuditJson(auditId);
                if (result.isSuccess() && result.getData() != null) {
                    JsonObject audit = result.getData();
                    if (audit.has("auditType")) {
                        return getJsonString(audit, "auditType");
                    }
                }
                return null;
            }
            
            @Override
            protected void done() {
                try {
                    String auditType = get();
                    if (auditType != null && !auditType.isEmpty()) {
                        selectedAuditType = auditType;
                        // Save it for next time
                        configManager.setDefaultAuditType(auditType);
                        // Update editor panel if it exists
                        if (editorPanel != null) {
                            editorPanel.setAuditType(auditType);
                        }
                        logging.logToOutput("Fetched audit type: " + auditType);
                    }
                } catch (Exception e) {
                    logging.logToError("Error fetching audit type: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    private static String getWindowTitle(String mode) {
        return switch (mode) {
            case "create" -> "PwnDoc – Create Finding";
            case "update" -> "PwnDoc – Update Finding";
            case "delete" -> "PwnDoc – Delete Finding";
            default -> "PwnDoc – Finding";
        };
    }
    
    private void initializeUI(boolean needsAuditSelection) {
        setSize(1000, 800);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Audit selector (shown if no default audit)
        auditSelectorPanel = createAuditSelectorPanel();
        auditSelectorPanel.setVisible(needsAuditSelection);
        
        // Workflow panel (shown after audit selected)
        workflowPanel = createWorkflowPanel();
        workflowPanel.setVisible(!needsAuditSelection);
        
        // Main layout - wrap in scroll pane for the workflow
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(auditSelectorPanel, BorderLayout.NORTH);
        contentPanel.add(workflowPanel, BorderLayout.CENTER);
        
        mainPanel.add(contentPanel, BorderLayout.CENTER);
        
        setContentPane(mainPanel);
    }
    
    private JPanel createAuditSelectorPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Select Default Audit"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        
        // Info label - plain text (no HTML)
        JLabel infoLabel = new JLabel("Please select a default audit before creating findings.");
        infoLabel.setForeground(Color.GRAY);
        
        // Table
        String[] columns = {"Name", "Type", "Company", "Date"};
        auditsTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        auditsTable = new JTable(auditsTableModel);
        auditsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        auditsTable.getSelectionModel().addListSelectionListener(e -> updateButtonStates());
        
        JScrollPane scrollPane = new JScrollPane(auditsTable);
        scrollPane.setPreferredSize(new Dimension(600, 150));
        
        // Status and buttons
        auditStatusBanner = new StatusBanner();
        
        makeDefaultButton = new JButton("Make Default & Continue");
        makeDefaultButton.setEnabled(false);
        makeDefaultButton.addActionListener(e -> setSelectedAsDefault());
        
        currentAuditLabel = new JLabel("Current default audit: None");
        currentAuditLabel.setFont(currentAuditLabel.getFont().deriveFont(Font.BOLD));
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(makeDefaultButton);
        
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(currentAuditLabel, BorderLayout.WEST);
        bottomPanel.add(buttonPanel, BorderLayout.EAST);
        
        panel.add(infoLabel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(auditStatusBanner, BorderLayout.SOUTH);
        panel.add(bottomPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createWorkflowPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        
        switch (mode) {
            case "create" -> panel.add(createCreateFindingPanel(), BorderLayout.CENTER);
            case "update" -> panel.add(createUpdateFindingPanel(), BorderLayout.CENTER);
            case "delete" -> panel.add(createDeleteFindingPanel(), BorderLayout.CENTER);
        }
        
        return panel;
    }
    
    /**
     * Create Finding panel with SINGLE scroll pane for entire content.
     */
    private JPanel createCreateFindingPanel() {
        JPanel outerPanel = new JPanel(new BorderLayout(10, 10));
        
        // Content panel that will be scrollable
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // Library panel
        libraryPanel = new FindingLibraryPanel(apiClient, logging, this::onFindingSelected);
        libraryPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        libraryPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 350));
        contentPanel.add(libraryPanel);
        
        // Load vulnerabilities when panel is shown
        SwingUtilities.invokeLater(() -> libraryPanel.loadVulnerabilities());
        
        // Spacing
        contentPanel.add(Box.createVerticalStrut(10));
        
        // Editor panel (initially hidden)
        editorPanel = new FindingEditorPanel(api, configManager, apiClient, logging, requestContext);
        editorPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        editorPanel.setVisible(false);
        
        // Set audit type if available
        if (selectedAuditType != null && !selectedAuditType.isEmpty()) {
            editorPanel.setAuditType(selectedAuditType);
        }
        
        contentPanel.add(editorPanel);
        
        // Wrap content in single scroll pane
        JScrollPane mainScrollPane = new JScrollPane(contentPanel);
        mainScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        mainScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mainScrollPane.getVerticalScrollBar().setUnitIncrement(16);
        mainScrollPane.setBorder(null);
        
        // Bottom buttons (outside scroll)
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton createButton = new JButton("Create Finding");
        createButton.addActionListener(e -> createFinding());
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        
        buttonPanel.add(cancelButton);
        buttonPanel.add(createButton);
        
        // Main status
        mainStatusBanner = new StatusBanner();
        
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(mainStatusBanner, BorderLayout.CENTER);
        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        outerPanel.add(mainScrollPane, BorderLayout.CENTER);
        outerPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        return outerPanel;
    }
    
    /**
     * Update Finding panel with SINGLE scroll pane for entire content.
     */
    private static final int FINDING_ID_COLUMN = 4;

    private JPanel createUpdateFindingPanel() {
        JPanel outerPanel = new JPanel(new BorderLayout(10, 10));
        
        // Content panel that will be scrollable
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // Findings list section
        JPanel listSection = new JPanel(new BorderLayout(5, 5));
        listSection.setBorder(BorderFactory.createTitledBorder("Select Finding to Update"));
        listSection.setAlignmentX(Component.LEFT_ALIGNMENT);
        listSection.setMaximumSize(new Dimension(Integer.MAX_VALUE, 250));
        
        String[] columns = {"Title", "Category", "Type", "Severity", "ID"};
        updateFindingsModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        updateFindingsTable = new JTable(updateFindingsModel);
        updateFindingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        // Hide ID column (used for reliable selection)
        updateFindingsTable.getColumnModel().getColumn(FINDING_ID_COLUMN).setMinWidth(0);
        updateFindingsTable.getColumnModel().getColumn(FINDING_ID_COLUMN).setMaxWidth(0);
        updateFindingsTable.getColumnModel().getColumn(FINDING_ID_COLUMN).setPreferredWidth(0);
        
        JScrollPane tableScroll = new JScrollPane(updateFindingsTable);
        tableScroll.setPreferredSize(new Dimension(600, 180));
        
        // Refresh button
        JPanel listControlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refreshFindingsButton = new JButton("Refresh");
        refreshFindingsButton.addActionListener(e -> {
            if (selectedAuditId != null) {
                findingsCache.remove(selectedAuditId);
            }
            loadFindingsWithCache(updateFindingsModel, updateFindingsTable, null, false);
        });
        listControlPanel.add(refreshFindingsButton);
        
        // Edit Selected button
        JButton editButton = new JButton("Edit Selected");
        editButton.setEnabled(false);
        updateFindingsTable.getSelectionModel().addListSelectionListener(e -> {
            editButton.setEnabled(updateFindingsTable.getSelectedRow() >= 0);
        });
        editButton.addActionListener(e -> {
            int viewRow = updateFindingsTable.getSelectedRow();
            if (viewRow >= 0) {
                int modelRow = updateFindingsTable.convertRowIndexToModel(viewRow);
                Object idValue = updateFindingsModel.getValueAt(modelRow, FINDING_ID_COLUMN);
                String selectedFindingId = idValue != null ? idValue.toString() : "";
                if (selectedFindingId.isEmpty()) {
                    mainStatusBanner.showError("Error", "Could not get finding ID - please refresh and try again");
                    return;
                }
                loadFindingForEdit(selectedFindingId);
            }
        });
        listControlPanel.add(editButton);
        
        listSection.add(listControlPanel, BorderLayout.NORTH);
        listSection.add(tableScroll, BorderLayout.CENTER);
        
        contentPanel.add(listSection);
        
        // Spacing
        contentPanel.add(Box.createVerticalStrut(10));
        
        // Editor panel (initially hidden)
        editorPanel = new FindingEditorPanel(api, configManager, apiClient, logging, requestContext);
        editorPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        editorPanel.setVisible(false);
        
        // Set audit type if available
        if (selectedAuditType != null && !selectedAuditType.isEmpty()) {
            editorPanel.setAuditType(selectedAuditType);
        }
        
        contentPanel.add(editorPanel);
        
        // Wrap content in single scroll pane
        JScrollPane mainScrollPane = new JScrollPane(contentPanel);
        mainScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        mainScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mainScrollPane.getVerticalScrollBar().setUnitIncrement(16);
        mainScrollPane.setBorder(null);
        
        // Bottom buttons (outside scroll)
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton saveButton = new JButton("Save Changes");
        saveButton.addActionListener(e -> updateFinding());
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        
        buttonPanel.add(cancelButton);
        buttonPanel.add(saveButton);
        
        mainStatusBanner = new StatusBanner();
        
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(mainStatusBanner, BorderLayout.CENTER);
        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        outerPanel.add(mainScrollPane, BorderLayout.CENTER);
        outerPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        // Load findings when panel is shown
        SwingUtilities.invokeLater(() -> loadFindingsWithCache(updateFindingsModel, updateFindingsTable, null, true));
        
        return outerPanel;
    }
    
    /**
     * Delete Finding panel.
     */
    private JPanel createDeleteFindingPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        
        // Findings list
        JPanel listPanel = new JPanel(new BorderLayout(5, 5));
        listPanel.setBorder(BorderFactory.createTitledBorder("Select Finding to Delete"));
        
        String[] columns = {"Title", "Category", "Type", "Severity", "ID"};
        DefaultTableModel findingsModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        JTable findingsTable = new JTable(findingsModel);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.getColumnModel().getColumn(FINDING_ID_COLUMN).setMinWidth(0);
        findingsTable.getColumnModel().getColumn(FINDING_ID_COLUMN).setMaxWidth(0);
        findingsTable.getColumnModel().getColumn(FINDING_ID_COLUMN).setPreferredWidth(0);
        
        JScrollPane scrollPane = new JScrollPane(findingsTable);
        scrollPane.setPreferredSize(new Dimension(600, 300));
        
        // Controls
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> {
            if (selectedAuditId != null) {
                findingsCache.remove(selectedAuditId);
            }
            loadFindingsWithCache(findingsModel, findingsTable, null, false);
        });
        controlPanel.add(refreshButton);
        
        listPanel.add(controlPanel, BorderLayout.NORTH);
        listPanel.add(scrollPane, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton deleteButton = new JButton("Delete Selected");
        deleteButton.setEnabled(false);
        deleteButton.setForeground(new Color(220, 53, 69));
        
        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            deleteButton.setEnabled(findingsTable.getSelectedRow() >= 0);
        });
        
        deleteButton.addActionListener(e -> {
            int viewRow = findingsTable.getSelectedRow();
            if (viewRow >= 0) {
                int modelRow = findingsTable.convertRowIndexToModel(viewRow);
                Object idValue = findingsModel.getValueAt(modelRow, FINDING_ID_COLUMN);
                String findingIdToDelete = idValue != null ? idValue.toString() : "";
                String title = findingsModel.getValueAt(modelRow, 0) != null ? findingsModel.getValueAt(modelRow, 0).toString() : "";
                
                if (findingIdToDelete.isEmpty()) {
                    mainStatusBanner.showError("Error", "Could not get finding ID - please refresh and try again");
                    return;
                }
                
                int confirm = JOptionPane.showConfirmDialog(
                    this,
                    "Are you sure you want to delete:\n\n\"" + title + "\"\n\nThis action cannot be undone.",
                    "Confirm Delete",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
                );
                
                if (confirm == JOptionPane.YES_OPTION) {
                    deleteFinding(findingIdToDelete, findingsModel, findingsTable);
                }
            }
        });
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        
        buttonPanel.add(cancelButton);
        buttonPanel.add(deleteButton);
        
        mainStatusBanner = new StatusBanner();
        
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(mainStatusBanner, BorderLayout.CENTER);
        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        panel.add(listPanel, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);
        
        // Load findings
        SwingUtilities.invokeLater(() -> loadFindingsWithCache(findingsModel, findingsTable, null, true));
        
        return panel;
    }
    
    // Called when a vulnerability is selected from the library
    private void onFindingSelected(JsonObject vulnerability) {
        if (vulnerability == null) return;
        
        // Set audit type on editor panel
        if (selectedAuditType != null && !selectedAuditType.isEmpty()) {
            editorPanel.setAuditType(selectedAuditType);
        }
        
        editorPanel.populateFromTemplate(vulnerability);
        editorPanel.setVisible(true);
        
        // Scroll to show editor
        SwingUtilities.invokeLater(() -> {
            editorPanel.scrollRectToVisible(new Rectangle(0, 0, 1, 1));
            revalidate();
            repaint();
        });
        
        mainStatusBanner.showSuccess("Finding template loaded - edit and click Create Finding");
    }
    
    private void loadFindingForEdit(String findingIdToEdit) {
        mainStatusBanner.showLoading("Loading finding details...");
        
        SwingWorker<ApiResult<JsonObject>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<JsonObject> doInBackground() {
                return apiClient.getFinding(selectedAuditId, findingIdToEdit);
            }
            
            @Override
            protected void done() {
                try {
                    ApiResult<JsonObject> result = get();
                    
                    if (result.isSuccess()) {
                        JsonObject finding = result.getData();
                        
                        // Set audit type on editor panel
                        if (selectedAuditType != null && !selectedAuditType.isEmpty()) {
                            editorPanel.setAuditType(selectedAuditType);
                        }
                        
                        // Set the finding ID for later update
                        editorPanel.setCurrentFindingId(findingIdToEdit);
                        
                        // Populate the editor with the finding data
                        editorPanel.populateFromFinding(finding);
                        
                        // Show the editor panel
                        editorPanel.setVisible(true);
                        
                        // Force layout update
                        SwingUtilities.invokeLater(() -> {
                            editorPanel.scrollRectToVisible(new Rectangle(0, 0, 1, 1));
                            revalidate();
                            repaint();
                        });
                        
                        mainStatusBanner.showSuccess("Finding loaded - edit and click Save Changes");
                    } else {
                        mainStatusBanner.showError("Failed to load finding", result.getError());
                    }
                } catch (Exception e) {
                    mainStatusBanner.showError("Error", e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    private void loadFindingsWithCache(DefaultTableModel model, JTable table, JButton actionButton, boolean useCache) {
        if (selectedAuditId == null || selectedAuditId.isEmpty()) {
            mainStatusBanner.showError("Error", "No audit selected");
            return;
        }
        
        // Check cache first
        if (useCache) {
            CachedFindings cached = findingsCache.get(selectedAuditId);
            if (cached != null && !cached.isExpired()) {
                populateFindingsTable(model, cached.findings);
                mainStatusBanner.hide();
                return;
            }
        }
        
        mainStatusBanner.showLoading("Loading findings...");
        
        SwingWorker<ApiResult<JsonObject>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<JsonObject> doInBackground() {
                return apiClient.getAuditJson(selectedAuditId);
            }
            
            @Override
            protected void done() {
                try {
                    ApiResult<JsonObject> result = get();
                    
                    if (result.isSuccess()) {
                        JsonObject audit = result.getData();
                        JsonArray findings = audit.has("findings") ? audit.getAsJsonArray("findings") : new JsonArray();
                        
                        // Store audit type
                        if (audit.has("auditType")) {
                            selectedAuditType = getJsonString(audit, "auditType");
                            // Update editor panel if it exists
                            if (editorPanel != null) {
                                editorPanel.setAuditType(selectedAuditType);
                            }
                        }
                        
                        // Cache the findings
                        findingsCache.put(selectedAuditId, new CachedFindings(findings));
                        
                        populateFindingsTable(model, findings);
                        mainStatusBanner.hide();
                    } else {
                        mainStatusBanner.showError("Failed to load findings", result.getError());
                    }
                } catch (Exception e) {
                    mainStatusBanner.showError("Error", e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    private void populateFindingsTable(DefaultTableModel model, JsonArray findings) {
        model.setRowCount(0);
        loadedFindings = findings;
        
        for (JsonElement el : findings) {
            if (el.isJsonObject()) {
                JsonObject finding = el.getAsJsonObject();
                String findingId = getFindingId(finding);
                model.addRow(new Object[]{
                    getJsonString(finding, "title"),
                    getJsonString(finding, "category"),
                    getJsonString(finding, "vulnType"),
                    getJsonString(finding, "severity"),
                    findingId
                });
            }
        }
    }
    
    private void createFinding() {
        if (editorPanel == null || !editorPanel.isVisible()) {
            mainStatusBanner.showError("Error", "Please select a finding template first");
            return;
        }
        
        mainStatusBanner.showLoading("Creating finding...");
        
        // First upload any proofs
        if (editorPanel.hasProofsToUpload()) {
            mainStatusBanner.showLoading("Uploading evidence files...");
            
            editorPanel.uploadPendingProofs(selectedAuditId, (success, imageIds) -> {
                if (!success) {
                    int proceed = JOptionPane.showConfirmDialog(
                        this,
                        "Some files failed to upload. Continue creating the finding anyway?",
                        "Upload Warning",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.WARNING_MESSAGE
                    );
                    if (proceed != JOptionPane.YES_OPTION) {
                        mainStatusBanner.showError("Cancelled", "Finding creation cancelled");
                        return;
                    }
                }
                
                // Now create the finding
                doCreateFinding(imageIds);
            });
        } else {
            doCreateFinding(null);
        }
    }
    
    private void doCreateFinding(List<String> imageIds) {
        mainStatusBanner.showLoading("Creating finding...");
        
        JsonObject findingData = editorPanel.getFindingData();
        
        // Build poc (Proof of Concept) HTML with embedded images
        if (imageIds != null && !imageIds.isEmpty()) {
            StringBuilder pocHtml = new StringBuilder();
            
            // Add each image as an HTML img tag
            for (String imageId : imageIds) {
                if (pocHtml.length() > 0) {
                    pocHtml.append("<p></p>"); // Add paragraph break
                }
                // PwnDoc image format: <img src="IMAGE_ID">
                pocHtml.append("<p><img src=\"").append(imageId).append("\"></p>");
            }
            
            findingData.addProperty("poc", pocHtml.toString());
            logging.logToOutput("Built poc HTML with " + imageIds.size() + " images: " + pocHtml.toString());
        }
        
        SwingWorker<ApiResult<JsonObject>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<JsonObject> doInBackground() {
                return apiClient.createFinding(selectedAuditId, findingData);
            }
            
            @Override
            protected void done() {
                try {
                    ApiResult<JsonObject> result = get();
                    
                    if (result.isSuccess()) {
                        // Invalidate cache
                        findingsCache.remove(selectedAuditId);
                        
                        mainStatusBanner.showSuccess("Finding created successfully!");
                        
                        // Close after delay
                        Timer timer = new Timer(1500, e -> dispose());
                        timer.setRepeats(false);
                        timer.start();
                    } else {
                        mainStatusBanner.showError("Failed to create finding", result.getError());
                    }
                } catch (Exception e) {
                    mainStatusBanner.showError("Error", e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    private void updateFinding() {
        if (editorPanel == null || editorPanel.getCurrentFindingId() == null) {
            mainStatusBanner.showError("Error", "No finding selected for update");
            return;
        }
        
        mainStatusBanner.showLoading("Updating finding...");
        
        // First upload any proofs
        if (editorPanel.hasProofsToUpload()) {
            mainStatusBanner.showLoading("Uploading evidence files...");
            
            editorPanel.uploadPendingProofs(selectedAuditId, (success, imageIds) -> {
                if (!success) {
                    int proceed = JOptionPane.showConfirmDialog(
                        this,
                        "Some files failed to upload. Continue updating the finding anyway?",
                        "Upload Warning",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.WARNING_MESSAGE
                    );
                    if (proceed != JOptionPane.YES_OPTION) {
                        mainStatusBanner.showError("Cancelled", "Finding update cancelled");
                        return;
                    }
                }
                
                doUpdateFinding(imageIds);
            });
        } else {
            doUpdateFinding(null);
        }
    }
    
    private void doUpdateFinding(List<String> imageIds) {
        mainStatusBanner.showLoading("Updating finding...");
        
        JsonObject findingData = editorPanel.getFindingData();
        String findingIdToUpdate = editorPanel.getCurrentFindingId();
        String existingPoc = editorPanel.getExistingPoc();
        
        // Build poc (Proof of Concept) HTML with embedded images
        StringBuilder pocHtml = new StringBuilder();
        
        // Preserve existing poc content
        if (existingPoc != null && !existingPoc.isEmpty()) {
            pocHtml.append(existingPoc);
        }
        
        // Add new images if any
        if (imageIds != null && !imageIds.isEmpty()) {
            for (String imageId : imageIds) {
                if (pocHtml.length() > 0) {
                    pocHtml.append("<p></p>"); // Add paragraph break
                }
                // PwnDoc image format: <img src="IMAGE_ID">
                pocHtml.append("<p><img src=\"").append(imageId).append("\"></p>");
            }
            logging.logToOutput("Built poc HTML with " + imageIds.size() + " new images");
        }
        
        // Always include poc in the update (to preserve existing content)
        if (pocHtml.length() > 0) {
            findingData.addProperty("poc", pocHtml.toString());
        }
        
        // Log what we're sending
        logging.logToOutput("=== UPDATE FINDING ===");
        logging.logToOutput("Audit ID: " + selectedAuditId);
        logging.logToOutput("Finding ID: " + findingIdToUpdate);
        logging.logToOutput("Finding Data: " + findingData.toString());
        
        SwingWorker<ApiResult<Void>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<Void> doInBackground() {
                return apiClient.updateFinding(selectedAuditId, findingIdToUpdate, findingData);
            }
            
            @Override
            protected void done() {
                try {
                    ApiResult<Void> result = get();
                    
                    if (result.isSuccess()) {
                        // Invalidate cache
                        findingsCache.remove(selectedAuditId);
                        
                        mainStatusBanner.showSuccess("Finding updated successfully!");
                        
                        // Close after delay
                        Timer timer = new Timer(1500, e -> dispose());
                        timer.setRepeats(false);
                        timer.start();
                    } else {
                        mainStatusBanner.showError("Failed to update finding", result.getError());
                    }
                } catch (Exception e) {
                    mainStatusBanner.showError("Error", e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    private void deleteFinding(String findingIdToDelete, DefaultTableModel model, JTable table) {
        mainStatusBanner.showLoading("Deleting finding...");
        
        SwingWorker<ApiResult<Void>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<Void> doInBackground() {
                return apiClient.deleteFinding(selectedAuditId, findingIdToDelete);
            }
            
            @Override
            protected void done() {
                try {
                    ApiResult<Void> result = get();
                    
                    if (result.isSuccess()) {
                        // Invalidate cache
                        findingsCache.remove(selectedAuditId);
                        
                        mainStatusBanner.showSuccess("Finding deleted successfully!");
                        
                        // Reload findings
                        loadFindingsWithCache(model, table, null, false);
                    } else {
                        mainStatusBanner.showError("Failed to delete finding", result.getError());
                    }
                } catch (Exception e) {
                    mainStatusBanner.showError("Error", e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    private void loadAudits() {
        auditStatusBanner.showLoading("Loading audits...");
        
        SwingWorker<ApiResult<List<Audit>>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<List<Audit>> doInBackground() {
                return apiClient.getAudits();
            }
            
            @Override
            protected void done() {
                try {
                    ApiResult<List<Audit>> result = get();
                    
                    if (result.isSuccess()) {
                        auditsTableModel.setRowCount(0);
                        for (Audit audit : result.getData()) {
                            auditsTableModel.addRow(new Object[]{
                                audit.name,
                                audit.auditType,
                                audit.company != null ? audit.company : "",
                                audit.date != null ? audit.date.substring(0, Math.min(10, audit.date.length())) : ""
                            });
                        }
                        auditStatusBanner.hide();
                        
                        // Update current default label
                        String defaultId = configManager.getDefaultAuditId();
                        if (defaultId != null && !defaultId.isEmpty()) {
                            currentAuditLabel.setText("Current default: " + configManager.getDefaultAuditName());
                        }
                    } else {
                        auditStatusBanner.showError("Failed to load audits", result.getError());
                    }
                } catch (Exception e) {
                    auditStatusBanner.showError("Error", e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    private void updateButtonStates() {
        makeDefaultButton.setEnabled(auditsTable.getSelectedRow() >= 0);
    }
    
    private void setSelectedAsDefault() {
        int row = auditsTable.getSelectedRow();
        if (row < 0) return;
        
        String auditName = (String) auditsTableModel.getValueAt(row, 0);
        String auditType = (String) auditsTableModel.getValueAt(row, 1);
        
        // Get audit ID by fetching audits again
        auditStatusBanner.showLoading("Setting default audit...");
        
        SwingWorker<ApiResult<List<Audit>>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<List<Audit>> doInBackground() {
                return apiClient.getAudits();
            }
            
            @Override
            protected void done() {
                try {
                    ApiResult<List<Audit>> result = get();
                    
                    if (result.isSuccess()) {
                        for (Audit audit : result.getData()) {
                            if (audit.name.equals(auditName)) {
                                selectedAuditId = audit.id;
                                selectedAuditName = audit.name;
                                selectedAuditType = audit.auditType;
                                
                                // Save to config
                                configManager.setDefaultAudit(audit.id, audit.name, audit.auditType);
                                
                                auditStatusBanner.showSuccess("Default audit set!");
                                
                                // Show workflow panel
                                showWorkflowPanel();
                                return;
                            }
                        }
                        auditStatusBanner.showError("Error", "Could not find audit");
                    } else {
                        auditStatusBanner.showError("Error", result.getError());
                    }
                } catch (Exception e) {
                    auditStatusBanner.showError("Error", e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    private void showWorkflowPanel() {
        auditSelectorPanel.setVisible(false);
        
        // Set audit type on editor panel before showing
        if (editorPanel != null && selectedAuditType != null) {
            editorPanel.setAuditType(selectedAuditType);
        }
        
        workflowPanel.setVisible(true);
        
        revalidate();
        repaint();
    }
    
    private String getJsonString(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) {
            return "";
        }
        return obj.get(key).getAsString();
    }
    
    /**
     * Returns the finding ID, handling variations in field naming.
     * Older audits may use "id" or "findingId" instead of "_id".
     */
    private String getFindingId(JsonObject finding) {
        if (finding == null) {
            return "";
        }
        String id = getJsonString(finding, "_id");
        if (!id.isEmpty()) return id;
        
        id = getJsonString(finding, "id");
        if (!id.isEmpty()) return id;
        
        return getJsonString(finding, "findingId");
    }
    
    // Cache class for findings
    private static class CachedFindings {
        final JsonArray findings;
        final long timestamp;
        
        CachedFindings(JsonArray findings) {
            this.findings = findings;
            this.timestamp = System.currentTimeMillis();
        }
        
        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_TTL_MS;
        }
    }
}
