/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.ui.panels;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.walidfaour.pwndoc.api.ApiResult;
import com.walidfaour.pwndoc.api.PwnDocApiClient;
import com.walidfaour.pwndoc.api.PwnDocApiClient.*;
import com.walidfaour.pwndoc.config.ConfigManager;
import com.walidfaour.pwndoc.ui.components.SectionHeader;
import com.walidfaour.pwndoc.ui.components.StatusBanner;
import com.walidfaour.pwndoc.util.TokenManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

/**
 * Audits management panel with table view and creation form.
 */
public class AuditsPanel {
    
    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final PwnDocApiClient apiClient;
    private final TokenManager tokenManager;
    private final Logging logging;
    
    private JPanel mainPanel;
    private JScrollPane scrollPane;
    
    // Select Default Audit section
    private JLabel defaultAuditLabel;
    private JCheckBox autoRefreshCheckbox;
    private JSpinner refreshIntervalSpinner;
    private JTable auditsTable;
    private AuditsTableModel tableModel;
    private JButton setDefaultButton;
    private JButton clearDefaultButton; // ISSUE #5: Button to clear default audit
    private JButton deleteAuditButton;
    private JButton sendForApprovalButton;
    private JButton refreshButton;
    private StatusBanner auditStatusBanner;
    
    // Create Audit section
    private JTextField auditNameField;
    private JComboBox<ComboItem> auditTypeCombo;
    private JComboBox<ComboItem> templateCombo;
    private JComboBox<ComboItem> companyCombo;
    private JComboBox<ComboItem> clientCombo;
    private JList<ComboItem> reviewersList;
    private DefaultListModel<ComboItem> reviewersListModel;
    private JTextArea scopeArea;
    private JTextField startDateField;
    private JTextField endDateField;
    private JPanel customFieldsPanel;
    private JButton createAuditButton;
    private JButton resetFormButton;
    private StatusBanner createStatusBanner;
    
    // Data caches
    private List<AuditType> auditTypes = new ArrayList<>();
    private List<Template> templates = new ArrayList<>();
    private List<Company> companies = new ArrayList<>();
    private List<Client> clients = new ArrayList<>();
    private List<User> reviewers = new ArrayList<>();
    private List<CustomField> customFields = new ArrayList<>();
    private Map<String, JComponent> customFieldComponents = new HashMap<>();
    private Map<String, String> customFieldTypes = new HashMap<>(); // Store fieldType for each field ID
    private Map<String, Boolean> customFieldRequired = new HashMap<>(); // Track if field is required
    
    // Polling
    private ScheduledExecutorService scheduler;
    private ScheduledFuture<?> pollingTask;
    private ScheduledFuture<?> customFieldsPollingTask;
    private volatile boolean isShuttingDown = false;
    private static final int CUSTOM_FIELDS_REFRESH_INTERVAL_SECONDS = 60; // Refresh custom fields every 60 seconds
    
    public AuditsPanel(MontoyaApi api, ConfigManager configManager,
                       PwnDocApiClient apiClient, TokenManager tokenManager, Logging logging) {
        this.api = api;
        this.configManager = configManager;
        this.apiClient = apiClient;
        this.tokenManager = tokenManager;
        this.logging = logging;
        this.scheduler = Executors.newSingleThreadScheduledExecutor();
        
        initializeUI();
    }
    
    private void initializeUI() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        mainPanel.add(createSelectDefaultAuditSection());
        mainPanel.add(Box.createVerticalStrut(20));
        mainPanel.add(createCreateAuditSection());
        mainPanel.add(Box.createVerticalGlue());
        
        scrollPane = new JScrollPane(mainPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
    }
    
    // ============ Select Default Audit Section ============
    
    private JPanel createSelectDefaultAuditSection() {
        JPanel section = new JPanel();
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            new EmptyBorder(10, 10, 10, 10)
        ));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        String helpText = """
            Select and manage audits.
            
            • Set as Default: Choose the active audit for creating, updating, and deleting findings
            • Delete Audit: Permanently remove an audit from PwnDoc
            • Send for Approval: Mark audit as ready for review
            • Clear Default: Click the gear icon and "Restore section defaults" to clear the current default
            
            The default audit is used as the target when creating, updating, or deleting findings 
            from Burp context menus (Proxy, Repeater). Without a default audit set, you will be 
            prompted to select one each time.
            """;
        
        SectionHeader header = new SectionHeader("Select Default Audit", helpText,
            () -> { configManager.resetAuditDefaults(); updateDefaultAuditLabel(); },
            () -> configManager.saveConfiguration(),
            () -> { configManager.reloadFromDisk(); updateDefaultAuditLabel(); }
        );
        section.add(header);
        section.add(Box.createVerticalStrut(10));
        
        // Status banner
        auditStatusBanner = new StatusBanner();
        section.add(auditStatusBanner);
        section.add(Box.createVerticalStrut(5));
        
        // Default audit label
        defaultAuditLabel = new JLabel();
        defaultAuditLabel.setFont(defaultAuditLabel.getFont().deriveFont(Font.BOLD));
        updateDefaultAuditLabel();
        section.add(defaultAuditLabel);
        section.add(Box.createVerticalStrut(10));
        
        // Auto-refresh controls
        JPanel refreshPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        refreshPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        autoRefreshCheckbox = new JCheckBox("Auto-refresh table");
        autoRefreshCheckbox.setSelected(configManager.isAutoRefreshAudits());
        autoRefreshCheckbox.addActionListener(e -> {
            configManager.setAutoRefreshAudits(autoRefreshCheckbox.isSelected());
            updatePolling();
        });
        refreshPanel.add(autoRefreshCheckbox);
        
        refreshPanel.add(new JLabel("Refresh interval (seconds):"));
        refreshIntervalSpinner = new JSpinner(new SpinnerNumberModel(
            configManager.getAuditRefreshIntervalSeconds(), 5, 300, 5));
        refreshIntervalSpinner.addChangeListener(e -> {
            configManager.setAuditRefreshIntervalSeconds((Integer) refreshIntervalSpinner.getValue());
            updatePolling();
        });
        refreshPanel.add(refreshIntervalSpinner);
        
        refreshButton = new JButton("Refresh Now");
        refreshButton.addActionListener(e -> refreshAudits());
        refreshPanel.add(refreshButton);
        
        section.add(refreshPanel);
        section.add(Box.createVerticalStrut(10));
        
        // Audits table
        tableModel = new AuditsTableModel();
        auditsTable = new JTable(tableModel);
        auditsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        auditsTable.getSelectionModel().addListSelectionListener(e -> updateButtonStates());
        
        // Custom renderer for checkmark columns
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        auditsTable.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);
        auditsTable.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
        
        // Set column widths
        auditsTable.getColumnModel().getColumn(0).setPreferredWidth(50);  // Default
        auditsTable.getColumnModel().getColumn(1).setPreferredWidth(200); // Name
        auditsTable.getColumnModel().getColumn(2).setPreferredWidth(120); // Type
        auditsTable.getColumnModel().getColumn(3).setPreferredWidth(120); // Company
        auditsTable.getColumnModel().getColumn(4).setPreferredWidth(150); // Participants
        auditsTable.getColumnModel().getColumn(5).setPreferredWidth(100); // Date
        auditsTable.getColumnModel().getColumn(6).setPreferredWidth(70);  // Approved
        
        JScrollPane tableScroll = new JScrollPane(auditsTable);
        tableScroll.setPreferredSize(new Dimension(800, 200));
        tableScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        section.add(tableScroll);
        section.add(Box.createVerticalStrut(10));
        
        // Action buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        setDefaultButton = new JButton("Set as Default");
        setDefaultButton.setEnabled(false);
        setDefaultButton.addActionListener(e -> setSelectedAsDefault());
        buttonPanel.add(setDefaultButton);
        
        // ISSUE #5 FIX: Add Clear Default button
        clearDefaultButton = new JButton("Clear Default");
        clearDefaultButton.setToolTipText("Remove the default audit selection");
        clearDefaultButton.addActionListener(e -> clearDefaultAudit());
        buttonPanel.add(clearDefaultButton);
        
        deleteAuditButton = new JButton("Delete Audit");
        deleteAuditButton.setEnabled(false);
        deleteAuditButton.addActionListener(e -> deleteSelectedAudit());
        buttonPanel.add(deleteAuditButton);
        
        sendForApprovalButton = new JButton("Send for Approval");
        sendForApprovalButton.setEnabled(false);
        sendForApprovalButton.addActionListener(e -> sendSelectedForApproval());
        buttonPanel.add(sendForApprovalButton);
        
        section.add(buttonPanel);
        
        return section;
    }
    
    private void updateDefaultAuditLabel() {
        String name = configManager.getDefaultAuditName();
        if (name != null && !name.isEmpty()) {
            defaultAuditLabel.setText("Current default audit: " + name);
        } else {
            defaultAuditLabel.setText("Current default audit: None");
        }
    }
    
    private void updateButtonStates() {
        int selectedRow = auditsTable.getSelectedRow();
        boolean hasSelection = selectedRow >= 0;
        
        setDefaultButton.setEnabled(hasSelection);
        deleteAuditButton.setEnabled(hasSelection);
        
        if (hasSelection) {
            Audit audit = tableModel.getAuditAt(selectedRow);
            sendForApprovalButton.setEnabled(audit != null && !audit.isApproved());
        } else {
            sendForApprovalButton.setEnabled(false);
        }
    }
    
    private void setSelectedAsDefault() {
        int selectedRow = auditsTable.getSelectedRow();
        if (selectedRow >= 0) {
            Audit audit = tableModel.getAuditAt(selectedRow);
            if (audit != null) {
                configManager.setDefaultAuditId(audit.id);
                configManager.setDefaultAuditName(audit.name);
                updateDefaultAuditLabel();
                tableModel.fireTableDataChanged();
                auditStatusBanner.showSuccess("Default audit set to: " + audit.name);
            }
        }
    }
    
    /**
     * ISSUE #5 FIX: Clears the default audit selection.
     * Allows users to remove the default audit so none is selected.
     */
    private void clearDefaultAudit() {
        String currentDefault = configManager.getDefaultAuditName();
        if (currentDefault == null || currentDefault.isEmpty()) {
            auditStatusBanner.showInfo("No default audit is currently set");
            return;
        }
        
        configManager.setDefaultAuditId("");
        configManager.setDefaultAuditName("");
        updateDefaultAuditLabel();
        tableModel.fireTableDataChanged();
        auditStatusBanner.showSuccess("Default audit cleared");
    }
    
    private void deleteSelectedAudit() {
        int selectedRow = auditsTable.getSelectedRow();
        if (selectedRow < 0) return;
        
        Audit audit = tableModel.getAuditAt(selectedRow);
        if (audit == null) return;
        
        int result = JOptionPane.showConfirmDialog(
            SwingUtilities.getWindowAncestor(mainPanel), // Use window ancestor for proper centering
            "Are you sure you want to delete audit: " + audit.name + "?\n" +
            "This action cannot be undone.",
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        
        if (result != JOptionPane.YES_OPTION) return;
        
        deleteAuditButton.setEnabled(false);
        auditStatusBanner.showLoading("Deleting audit...");
        
        SwingWorker<ApiResult<Void>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<Void> doInBackground() {
                return apiClient.deleteAudit(audit.id);
            }
            
            @Override
            protected void done() {
                try {
                    ApiResult<Void> result = get();
                    if (result.isSuccess()) {
                        // Clear default if we deleted it
                        if (audit.id.equals(configManager.getDefaultAuditId())) {
                            configManager.setDefaultAuditId("");
                            configManager.setDefaultAuditName("");
                            updateDefaultAuditLabel();
                        }
                        auditStatusBanner.showSuccess("Audit deleted successfully");
                        refreshAudits();
                    } else {
                        auditStatusBanner.showError("Delete failed", result.getError());
                        updateButtonStates();
                    }
                } catch (Exception e) {
                    auditStatusBanner.showError("Delete failed", e.getMessage());
                    updateButtonStates();
                }
            }
        };
        worker.execute();
    }
    
    private void sendSelectedForApproval() {
        int selectedRow = auditsTable.getSelectedRow();
        if (selectedRow < 0) return;
        
        Audit audit = tableModel.getAuditAt(selectedRow);
        if (audit == null || audit.isApproved()) return;
        
        sendForApprovalButton.setEnabled(false);
        auditStatusBanner.showLoading("Sending for approval...");
        
        SwingWorker<ApiResult<Void>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<Void> doInBackground() {
                // Try updateReadyForReview first, then toggleApproval as fallback
                ApiResult<Void> result = apiClient.updateReadyForReview(audit.id, true);
                if (result.isFailure() && result.getError().contains("404")) {
                    // Endpoint not available, try toggle
                    result = apiClient.toggleAuditApproval(audit.id);
                }
                return result;
            }
            
            @Override
            protected void done() {
                try {
                    ApiResult<Void> result = get();
                    if (result.isSuccess()) {
                        auditStatusBanner.showSuccess("Audit sent for approval");
                        refreshAudits();
                    } else {
                        if (result.getError().contains("404") || result.getError().contains("not supported")) {
                            auditStatusBanner.showError("Approval not supported", 
                                "The approval endpoint is not available on this PwnDoc server");
                        } else {
                            auditStatusBanner.showError("Approval failed", result.getError());
                        }
                        updateButtonStates();
                    }
                } catch (Exception e) {
                    auditStatusBanner.showError("Approval failed", e.getMessage());
                    updateButtonStates();
                }
            }
        };
        worker.execute();
    }
    
    // ============ Create Audit Section ============
    
    private JPanel createCreateAuditSection() {
        JPanel section = new JPanel();
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            new EmptyBorder(10, 10, 10, 10)
        ));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        String helpText = """
            Create a new audit in PwnDoc.
            
            Required fields:
            • Audit Name: Descriptive name for the audit
            • Assessment Type: Type of security assessment
            • Template: Report template to use
            • Company: Target company
            • Start Date: When the audit begins
            
            Optional fields will be populated from PwnDoc server data.
            """;
        
        SectionHeader header = new SectionHeader("Create Audit", helpText, null, null, null);
        section.add(header);
        section.add(Box.createVerticalStrut(10));
        
        // Status banner
        createStatusBanner = new StatusBanner();
        section.add(createStatusBanner);
        section.add(Box.createVerticalStrut(5));
        
        // Form
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        
        int row = 0;
        
        // Audit Name
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Audit Name: *"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        auditNameField = new JTextField(30);
        formPanel.add(auditNameField, gbc);
        row++;
        
        // Assessment Type
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Assessment Type: *"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        auditTypeCombo = new JComboBox<>();
        formPanel.add(auditTypeCombo, gbc);
        row++;
        
        // Template
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Template: *"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        templateCombo = new JComboBox<>();
        formPanel.add(templateCombo, gbc);
        row++;
        
        // Company
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Company: *"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        companyCombo = new JComboBox<>();
        formPanel.add(companyCombo, gbc);
        row++;
        
        // Client
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("Client:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        clientCombo = new JComboBox<>();
        clientCombo.addItem(new ComboItem("", "(None)"));
        formPanel.add(clientCombo, gbc);
        row++;
        
        // Reviewers
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        formPanel.add(new JLabel("Reviewers:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = GridBagConstraints.WEST;
        reviewersListModel = new DefaultListModel<>();
        reviewersList = new JList<>(reviewersListModel);
        reviewersList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        reviewersList.setVisibleRowCount(3);
        JScrollPane reviewersScroll = new JScrollPane(reviewersList);
        reviewersScroll.setPreferredSize(new Dimension(200, 60));
        formPanel.add(reviewersScroll, gbc);
        row++;
        
        // Scope
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        formPanel.add(new JLabel("Scope:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = GridBagConstraints.WEST;
        scopeArea = new JTextArea(3, 30);
        scopeArea.setLineWrap(true);
        JScrollPane scopeScroll = new JScrollPane(scopeArea);
        formPanel.add(scopeScroll, gbc);
        row++;
        
        // Start Date (required - pre-filled with today)
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.WEST;
        formPanel.add(new JLabel("Start Date: *"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        JPanel startDatePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        startDatePanel.setOpaque(false);
        startDateField = new JTextField(10);
        startDateField.setText(new SimpleDateFormat("yyyy-MM-dd").format(new Date()));
        startDateField.setToolTipText("Format: YYYY-MM-DD");
        JButton startPickerBtn = new JButton("📅");
        startPickerBtn.setMargin(new Insets(2, 4, 2, 4));
        startPickerBtn.addActionListener(e -> showDatePicker(startDateField));
        startDatePanel.add(startDateField);
        startDatePanel.add(startPickerBtn);
        formPanel.add(startDatePanel, gbc);
        row++;
        
        // End Date (optional - empty by default)
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        formPanel.add(new JLabel("End Date:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        JPanel endDatePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        endDatePanel.setOpaque(false);
        endDateField = new JTextField(10);
        endDateField.setToolTipText("Format: YYYY-MM-DD (optional)");
        JButton endPickerBtn = new JButton("📅");
        endPickerBtn.setMargin(new Insets(2, 4, 2, 4));
        endPickerBtn.addActionListener(e -> showDatePicker(endDateField));
        JButton endClearBtn = new JButton("✕");
        endClearBtn.setMargin(new Insets(2, 4, 2, 4));
        endClearBtn.setToolTipText("Clear date");
        endClearBtn.addActionListener(e -> endDateField.setText(""));
        endDatePanel.add(endDateField);
        endDatePanel.add(endPickerBtn);
        endDatePanel.add(endClearBtn);
        formPanel.add(endDatePanel, gbc);
        row++;
        
        section.add(formPanel);
        
        // Custom fields panel (dynamically populated)
        customFieldsPanel = new JPanel();
        customFieldsPanel.setLayout(new BoxLayout(customFieldsPanel, BoxLayout.Y_AXIS));
        customFieldsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        customFieldsPanel.setBorder(BorderFactory.createTitledBorder("Custom Fields"));
        customFieldsPanel.setVisible(false);
        section.add(Box.createVerticalStrut(10));
        section.add(customFieldsPanel);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        createAuditButton = new JButton("Create Audit");
        createAuditButton.addActionListener(e -> createAudit());
        buttonPanel.add(createAuditButton);
        
        resetFormButton = new JButton("Reset Form");
        resetFormButton.addActionListener(e -> resetForm());
        buttonPanel.add(resetFormButton);
        
        section.add(Box.createVerticalStrut(10));
        section.add(buttonPanel);
        
        return section;
    }
    
    private void createAudit() {
        // Validate required fields
        String name = auditNameField.getText().trim();
        if (name.isEmpty()) {
            createStatusBanner.showError("Validation Error", "Audit name is required");
            return;
        }
        
        ComboItem typeItem = (ComboItem) auditTypeCombo.getSelectedItem();
        if (typeItem == null || typeItem.id.isEmpty()) {
            createStatusBanner.showError("Validation Error", "Assessment type is required");
            return;
        }
        
        ComboItem templateItem = (ComboItem) templateCombo.getSelectedItem();
        if (templateItem == null || templateItem.id.isEmpty()) {
            createStatusBanner.showError("Validation Error", "Template is required");
            return;
        }
        
        ComboItem companyItem = (ComboItem) companyCombo.getSelectedItem();
        if (companyItem == null || companyItem.id.isEmpty()) {
            createStatusBanner.showError("Validation Error", "Company is required");
            return;
        }
        
        createAuditButton.setEnabled(false);
        createStatusBanner.showLoading("Creating audit...");
        
        SwingWorker<ApiResult<Audit>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<Audit> doInBackground() {
                // First create the audit
                ApiResult<Audit> createResult = apiClient.createAudit(name, typeItem.name, "en");
                if (createResult.isFailure()) {
                    return createResult;
                }
                
                Audit audit = createResult.getData();
                logging.logToOutput("Audit created with ID: " + audit.id);
                
                // CRITICAL: Fetch the audit's initialized customFields FIRST
                // PwnDoc auto-creates customFields with full structure when audit is created
                // We need to preserve that full structure and only update the text values
                ApiResult<JsonObject> auditGeneral = apiClient.getAuditGeneralJson(audit.id);
                JsonArray existingCustomFields = null;
                if (auditGeneral.isSuccess() && auditGeneral.getData().has("customFields")) {
                    existingCustomFields = auditGeneral.getData().getAsJsonArray("customFields");
                    logging.logToOutput("Fetched " + existingCustomFields.size() + " customFields with full structure");
                }
                
                // Then update with additional details
                JsonObject updates = new JsonObject();
                updates.addProperty("name", name);
                updates.addProperty("template", templateItem.id);
                
                // Company - send as object with _id (like reviewers)
                JsonObject companyObj = new JsonObject();
                companyObj.addProperty("_id", companyItem.id);
                updates.add("company", companyObj);
                logging.logToOutput("Company: " + companyItem.name + " (ID: " + companyItem.id + ")");
                
                ComboItem clientItem = (ComboItem) clientCombo.getSelectedItem();
                if (clientItem != null && !clientItem.id.isEmpty()) {
                    // Client - just the ID string
                    updates.addProperty("client", clientItem.id);
                    logging.logToOutput("Client: " + clientItem.name + " (ID: " + clientItem.id + ")");
                }
                
                // Reviewers - must be array of objects with _id
                List<ComboItem> selectedReviewers = reviewersList.getSelectedValuesList();
                if (!selectedReviewers.isEmpty()) {
                    JsonArray reviewersArray = new JsonArray();
                    for (ComboItem r : selectedReviewers) {
                        JsonObject reviewerObj = new JsonObject();
                        reviewerObj.addProperty("_id", r.id);
                        reviewersArray.add(reviewerObj);
                    }
                    updates.add("reviewers", reviewersArray);
                }
                
                // Scope - array of plain strings
                String scopeText = scopeArea.getText().trim();
                if (!scopeText.isEmpty()) {
                    JsonArray scopeArray = new JsonArray();
                    for (String line : scopeText.split("\\n")) {
                        if (!line.trim().isEmpty()) {
                            scopeArray.add(line.trim());
                        }
                    }
                    updates.add("scope", scopeArray);
                }
                
                // Dates
                String startDateStr = startDateField.getText().trim();
                if (!startDateStr.isEmpty()) {
                    updates.addProperty("date_start", startDateStr);
                }
                
                String endDateStr = endDateField.getText().trim();
                if (!endDateStr.isEmpty()) {
                    updates.addProperty("date_end", endDateStr);
                }
                
                // Custom fields - PRESERVE FULL STRUCTURE, only update text values
                // PwnDoc UI requires the complete customField object (with _id, fieldType, label, options, etc.)
                if (existingCustomFields != null && !customFieldComponents.isEmpty()) {
                    logging.logToOutput("Updating customField text values (preserving full structure):");
                    
                    // Build map of our values
                    Map<String, Object> ourValues = new HashMap<>();
                    for (Map.Entry<String, JComponent> entry : customFieldComponents.entrySet()) {
                        String fieldId = entry.getKey();
                        String fieldType = customFieldTypes.getOrDefault(fieldId, "text");
                        JComponent component = entry.getValue();
                        
                        if (isArrayFieldType(fieldType)) {
                            ourValues.put(fieldId, getCustomFieldArrayValue(component, fieldType));
                        } else {
                            ourValues.put(fieldId, getCustomFieldStringValue(component));
                        }
                    }
                    
                    // Update text values in existing structure (keeping full customField objects)
                    for (int i = 0; i < existingCustomFields.size(); i++) {
                        JsonObject cf = existingCustomFields.get(i).getAsJsonObject();
                        
                        // customField is a FULL OBJECT with _id, fieldType, label, options, etc.
                        JsonElement customFieldElement = cf.get("customField");
                        String fieldId = null;
                        
                        if (customFieldElement.isJsonObject()) {
                            JsonObject customFieldObj = customFieldElement.getAsJsonObject();
                            if (customFieldObj.has("_id")) {
                                fieldId = customFieldObj.get("_id").getAsString();
                            }
                        } else if (customFieldElement.isJsonPrimitive()) {
                            // Fallback if it's just an ID string
                            fieldId = customFieldElement.getAsString();
                        }
                        
                        if (fieldId != null && ourValues.containsKey(fieldId)) {
                            Object value = ourValues.get(fieldId);
                            // Remove old text and add new value
                            cf.remove("text");
                            if (value instanceof JsonArray) {
                                cf.add("text", (JsonArray) value);
                                logging.logToOutput("  - Updated " + fieldId + " = " + value);
                            } else {
                                cf.addProperty("text", value.toString());
                                logging.logToOutput("  - Updated " + fieldId + " = " + value);
                            }
                        }
                    }
                    
                    // Send the COMPLETE structure back (with full customField objects)
                    updates.add("customFields", existingCustomFields);
                    logging.logToOutput("Sending " + existingCustomFields.size() + " customFields with full structure");
                }
                
                // Log what we're sending
                logging.logToOutput("Full update payload: " + updates.toString().substring(0, Math.min(500, updates.toString().length())) + "...");
                
                ApiResult<Void> updateResult = apiClient.updateAuditGeneral(audit.id, updates);
                logging.logToOutput("Update result: " + (updateResult.isSuccess() ? "SUCCESS" : "FAILED: " + updateResult.getError()));
                if (updateResult.isFailure()) {
                    return ApiResult.failure("Audit created but update failed: " + updateResult.getError());
                }
                
                return createResult;
            }
            
            @Override
            protected void done() {
                createAuditButton.setEnabled(true);
                try {
                    ApiResult<Audit> result = get();
                    if (result.isSuccess()) {
                        createStatusBanner.showSuccess("Audit created: " + result.getData().name);
                        resetForm();
                        refreshAudits();
                    } else {
                        createStatusBanner.showError("Creation failed", result.getError());
                    }
                } catch (Exception e) {
                    createStatusBanner.showError("Creation failed", e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    private boolean isArrayFieldType(String fieldType) {
        return fieldType != null && (
            fieldType.contains("multi") || 
            fieldType.equals("checkbox") || 
            fieldType.equals("boolean") || 
            fieldType.equals("bool")
        );
    }
    
    private String getCustomFieldStringValue(JComponent component) {
        if (component instanceof JTextField tf) {
            return tf.getText();
        } else if (component instanceof JTextArea ta) {
            return ta.getText();
        } else if (component instanceof JSpinner sp) {
            Object val = sp.getValue();
            if (val instanceof Date d) {
                return new SimpleDateFormat("yyyy-MM-dd").format(d);
            }
            return val.toString();
        } else if (component instanceof JComboBox<?> cb) {
            Object sel = cb.getSelectedItem();
            return sel != null ? sel.toString() : "";
        } else if (component instanceof JCheckBox chk) {
            // For single checkbox returning string (shouldn't happen, but fallback)
            return chk.isSelected() ? "True" : "";
        } else if (component instanceof JScrollPane scroll) {
            Component view = scroll.getViewport().getView();
            if (view instanceof JTextArea ta) {
                return ta.getText();
            }
        } else if (component instanceof JPanel panel) {
            // Check if it's a date picker panel
            Object dateFieldObj = panel.getClientProperty("dateField");
            if (dateFieldObj instanceof JTextField tf) {
                return tf.getText();
            }
            // Spacer/separator - no value
            return "";
        }
        return "";
    }
    
    private JsonArray getCustomFieldArrayValue(JComponent component, String fieldType) {
        JsonArray array = new JsonArray();
        
        if (component instanceof JCheckBox chk) {
            // Checkbox: ["True"] when checked, [] when unchecked
            if (chk.isSelected()) {
                array.add("True");
            }
        } else if (component instanceof JList<?> list) {
            List<?> selected = list.getSelectedValuesList();
            for (Object item : selected) {
                array.add(item.toString());
            }
        } else if (component instanceof JScrollPane scroll) {
            Component view = scroll.getViewport().getView();
            if (view instanceof JList<?> list) {
                List<?> selected = list.getSelectedValuesList();
                for (Object item : selected) {
                    array.add(item.toString());
                }
            }
        }
        
        return array;
    }
    
    // Keep old method for compatibility with resetForm
    private String getCustomFieldValue(JComponent component) {
        return getCustomFieldStringValue(component);
    }
    
    private void resetForm() {
        auditNameField.setText("");
        auditTypeCombo.setSelectedIndex(auditTypeCombo.getItemCount() > 0 ? 0 : -1);
        templateCombo.setSelectedIndex(templateCombo.getItemCount() > 0 ? 0 : -1);
        companyCombo.setSelectedIndex(companyCombo.getItemCount() > 0 ? 0 : -1);
        clientCombo.setSelectedIndex(0);
        reviewersList.clearSelection();
        scopeArea.setText("");
        startDateField.setText(new SimpleDateFormat("yyyy-MM-dd").format(new Date()));
        endDateField.setText(""); // Optional - leave empty
        
        // Reset custom fields
        for (JComponent component : customFieldComponents.values()) {
            if (component instanceof JTextField tf) {
                tf.setText("");
            } else if (component instanceof JTextArea ta) {
                ta.setText("");
            } else if (component instanceof JSpinner sp) {
                if (sp.getModel() instanceof SpinnerDateModel) {
                    sp.setValue(new Date());
                } else {
                    sp.setValue(0);
                }
            } else if (component instanceof JComboBox<?> cb) {
                if (cb.getItemCount() > 0) cb.setSelectedIndex(0);
            } else if (component instanceof JCheckBox chk) {
                chk.setSelected(false);
            } else if (component instanceof JList<?> list) {
                list.clearSelection();
            } else if (component instanceof JScrollPane scroll) {
                Component view = scroll.getViewport().getView();
                if (view instanceof JTextArea ta) {
                    ta.setText("");
                } else if (view instanceof JList<?> list) {
                    list.clearSelection();
                }
            }
        }
    }
    
    // ============ Data Loading ============
    
    public void onAuthenticationSuccess() {
        loadFormData();
        refreshAudits();
        updatePolling();
    }
    
    /**
     * Called when authentication fails.
     * ISSUE #2 & #6 FIX: Stops polling, clears audit table, and updates UI
     * to prevent using stale data from old tokens.
     */
    public void onAuthenticationFailure() {
        // Cancel any active polling tasks
        if (pollingTask != null) {
            pollingTask.cancel(false);
            pollingTask = null;
        }
        if (customFieldsPollingTask != null) {
            customFieldsPollingTask.cancel(false);
            customFieldsPollingTask = null;
        }
        
        // Clear the audits table
        tableModel.setAudits(new ArrayList<>());
        
        // Update button states
        updateButtonStates();
        
        // Show status message
        auditStatusBanner.showError("Authentication required", 
            "Please authenticate in the General tab to view audits.");
        
        logging.logToOutput("Auth failure - stopped polling and cleared audit data");
    }
    
    private void loadFormData() {
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                // Load all form data in background
                ApiResult<List<AuditType>> typesResult = apiClient.getAuditTypes();
                if (typesResult.isSuccess()) {
                    auditTypes = typesResult.getData();
                }
                
                ApiResult<List<Template>> templatesResult = apiClient.getTemplates();
                if (templatesResult.isSuccess()) {
                    templates = templatesResult.getData();
                }
                
                ApiResult<List<Company>> companiesResult = apiClient.getCompanies();
                if (companiesResult.isSuccess()) {
                    companies = companiesResult.getData();
                }
                
                ApiResult<List<Client>> clientsResult = apiClient.getClients();
                if (clientsResult.isSuccess()) {
                    clients = clientsResult.getData();
                }
                
                ApiResult<List<User>> reviewersResult = apiClient.getReviewers();
                if (reviewersResult.isSuccess()) {
                    reviewers = reviewersResult.getData();
                }
                
                ApiResult<List<CustomField>> fieldsResult = apiClient.getCustomFields();
                if (fieldsResult.isSuccess()) {
                    customFields = fieldsResult.getData();
                }
                
                return null;
            }
            
            @Override
            protected void done() {
                populateFormDropdowns();
            }
        };
        worker.execute();
    }
    
    private void populateFormDropdowns() {
        // Audit types
        auditTypeCombo.removeAllItems();
        for (AuditType type : auditTypes) {
            auditTypeCombo.addItem(new ComboItem(type.name, type.name));
        }
        
        // Templates
        templateCombo.removeAllItems();
        for (Template template : templates) {
            templateCombo.addItem(new ComboItem(template.id, template.name));
        }
        
        // Companies
        companyCombo.removeAllItems();
        for (Company company : companies) {
            String display = company.name;
            if (company.shortName != null && !company.shortName.isEmpty()) {
                display += " (" + company.shortName + ")";
            }
            companyCombo.addItem(new ComboItem(company.id, display));
        }
        
        // Clients
        clientCombo.removeAllItems();
        clientCombo.addItem(new ComboItem("", "(None)"));
        for (Client client : clients) {
            clientCombo.addItem(new ComboItem(client.id, client.getDisplayName()));
        }
        
        // Reviewers
        reviewersListModel.clear();
        for (User reviewer : reviewers) {
            reviewersListModel.addElement(new ComboItem(reviewer.id, reviewer.getDisplayName()));
        }
        
        // Custom fields
        buildCustomFieldsPanel();
    }
    
    private void buildCustomFieldsPanel() {
        customFieldsPanel.removeAll();
        customFieldComponents.clear();
        customFieldTypes.clear(); // Clear field types map too
        customFieldRequired.clear(); // Clear required flags map too
        
        if (customFields.isEmpty()) {
            customFieldsPanel.setVisible(false);
            logging.logToOutput("No custom fields available");
            return;
        }
        
        logging.logToOutput("Processing " + customFields.size() + " custom fields:");
        for (CustomField f : customFields) {
            logging.logToOutput("  - " + f.label + " (type: " + f.fieldType + ", display: " + f.display + ", displaySub: " + f.displaySub + ")");
        }
        
        // Filter for audit-level custom fields
        // Include fields where display is "audit" or "general", or displaySub contains "general" or "audit"
        List<CustomField> auditFields = customFields.stream()
            .filter(f -> {
                String display = f.display != null ? f.display.toLowerCase() : "";
                String displaySub = f.displaySub != null ? f.displaySub.toLowerCase() : "";
                return display.contains("audit") || display.contains("general") ||
                       displaySub.contains("audit") || displaySub.contains("general") ||
                       display.isEmpty(); // Include fields with no specific display setting
            })
            .toList();
        
        logging.logToOutput("Filtered to " + auditFields.size() + " audit-level custom fields");
        
        if (auditFields.isEmpty()) {
            customFieldsPanel.setVisible(false);
            return;
        }
        
        JPanel fieldsGrid = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        
        int row = 0;
        for (CustomField field : auditFields) {
            // Skip space/separator fields in the label column
            if ("space".equals(field.fieldType)) {
                gbc.gridx = 0; gbc.gridy = row;
                gbc.gridwidth = 2;
                gbc.fill = GridBagConstraints.HORIZONTAL;
                JPanel spacer = new JPanel();
                spacer.setPreferredSize(new Dimension(1, 15));
                fieldsGrid.add(spacer, gbc);
                gbc.gridwidth = 1;
                row++;
                continue;
            }
            
            gbc.gridx = 0; gbc.gridy = row;
            gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
            
            // Create label with required indicator
            String labelText = field.label + (field.required ? " *:" : ":");
            JLabel label = new JLabel(labelText);
            
            // Add tooltip if description exists
            if (field.description != null && !field.description.isEmpty()) {
                label.setToolTipText(field.description);
            }
            
            fieldsGrid.add(label, gbc);
            
            gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
            JComponent component = createCustomFieldComponent(field);
            
            // Add tooltip to component too
            if (field.description != null && !field.description.isEmpty() && component instanceof JComponent jc) {
                jc.setToolTipText(field.description);
            }
            
            fieldsGrid.add(component, gbc);
            customFieldComponents.put(field.id, component);
            customFieldTypes.put(field.id, field.fieldType != null ? field.fieldType.toLowerCase() : "text");
            customFieldRequired.put(field.id, field.required);
            
            row++;
        }
        
        customFieldsPanel.add(fieldsGrid);
        customFieldsPanel.setVisible(true);
        customFieldsPanel.revalidate();
        customFieldsPanel.repaint();
    }
    
    private JComponent createCustomFieldComponent(CustomField field) {
        String type = field.fieldType != null ? field.fieldType.toLowerCase() : "text";
        
        return switch (type) {
            case "text", "input", "string" -> {
                JTextField textField = new JTextField(25);
                textField.setMaximumSize(new Dimension(300, 25));
                yield textField;
            }
            case "number", "integer" -> {
                JSpinner spinner = new JSpinner(new SpinnerNumberModel(0, 0, Integer.MAX_VALUE, 1));
                spinner.setPreferredSize(new Dimension(100, 25));
                yield spinner;
            }
            case "date" -> {
                // Create a panel with text field and date picker button
                JPanel datePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
                datePanel.setOpaque(false);
                
                JTextField dateField = new JTextField(10);
                dateField.setToolTipText("Format: YYYY-MM-DD");
                // Only pre-fill if required
                if (field.required) {
                    dateField.setText(new SimpleDateFormat("yyyy-MM-dd").format(new Date()));
                }
                
                JButton pickerBtn = new JButton("📅");
                pickerBtn.setMargin(new Insets(2, 4, 2, 4));
                pickerBtn.setToolTipText("Open date picker");
                pickerBtn.addActionListener(e -> showDatePicker(dateField));
                
                JButton clearBtn = new JButton("✕");
                clearBtn.setMargin(new Insets(2, 4, 2, 4));
                clearBtn.setToolTipText("Clear date");
                clearBtn.addActionListener(e -> dateField.setText(""));
                
                datePanel.add(dateField);
                datePanel.add(pickerBtn);
                datePanel.add(clearBtn);
                
                // Store the text field reference for value extraction
                datePanel.putClientProperty("dateField", dateField);
                yield datePanel;
            }
            case "select", "select-single", "combo" -> {
                JComboBox<String> combo = new JComboBox<>();
                combo.addItem(""); // Empty option
                if (field.options != null) {
                    for (String opt : field.options) {
                        combo.addItem(opt);
                    }
                }
                combo.setPreferredSize(new Dimension(200, 25));
                yield combo;
            }
            case "select-multi", "multi-select", "select-multiple", "multiselect" -> {
                DefaultListModel<String> model = new DefaultListModel<>();
                if (field.options != null) {
                    for (String opt : field.options) {
                        model.addElement(opt);
                    }
                }
                JList<String> list = new JList<>(model);
                list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
                list.setVisibleRowCount(Math.min(4, model.size()));
                JScrollPane scroll = new JScrollPane(list);
                scroll.setPreferredSize(new Dimension(200, 80));
                yield scroll;
            }
            case "checkbox", "boolean", "bool" -> new JCheckBox();
            case "radio" -> {
                // For radio, use a combo box as simpler alternative
                JComboBox<String> combo = new JComboBox<>();
                if (field.options != null) {
                    for (String opt : field.options) {
                        combo.addItem(opt);
                    }
                }
                combo.setPreferredSize(new Dimension(200, 25));
                yield combo;
            }
            case "editor", "textarea", "text-area", "richtext", "html" -> {
                // Rich text editor - use JTextArea for multi-line input
                JTextArea textArea = new JTextArea(4, 30);
                textArea.setLineWrap(true);
                textArea.setWrapStyleWord(true);
                JScrollPane scroll = new JScrollPane(textArea);
                scroll.setPreferredSize(new Dimension(350, 100));
                scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                yield scroll;
            }
            case "space", "separator" -> {
                // Just a separator/spacer
                JPanel spacer = new JPanel();
                spacer.setPreferredSize(new Dimension(1, 10));
                yield spacer;
            }
            default -> {
                // Default to text field
                logging.logToOutput("Unknown custom field type: " + type + " for field: " + field.label);
                JTextField textField = new JTextField(25);
                yield textField;
            }
        };
    }
    
    private void showDatePicker(JTextField dateField) {
        // Create a simple date picker dialog
        Window window = SwingUtilities.getWindowAncestor(dateField);
        JDialog dialog = new JDialog(window, "Select Date", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(5, 5));
        
        // Parse existing date or use today
        Calendar cal = Calendar.getInstance();
        String existingDate = dateField.getText().trim();
        if (!existingDate.isEmpty()) {
            try {
                Date d = new SimpleDateFormat("yyyy-MM-dd").parse(existingDate);
                cal.setTime(d);
            } catch (Exception ignored) {}
        }
        
        // Year/Month selectors
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        
        JButton prevMonth = new JButton("<");
        JButton nextMonth = new JButton(">");
        JLabel monthYearLabel = new JLabel();
        monthYearLabel.setFont(monthYearLabel.getFont().deriveFont(Font.BOLD, 14f));
        
        topPanel.add(prevMonth);
        topPanel.add(monthYearLabel);
        topPanel.add(nextMonth);
        
        // Calendar grid
        JPanel calendarPanel = new JPanel(new GridLayout(7, 7, 2, 2));
        calendarPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        
        // Day headers
        String[] days = {"Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"};
        for (String day : days) {
            JLabel lbl = new JLabel(day, SwingConstants.CENTER);
            lbl.setFont(lbl.getFont().deriveFont(Font.BOLD));
            calendarPanel.add(lbl);
        }
        
        // Day buttons (will be populated by updateCalendar)
        JButton[] dayButtons = new JButton[42];
        for (int i = 0; i < 42; i++) {
            dayButtons[i] = new JButton();
            dayButtons[i].setMargin(new Insets(2, 2, 2, 2));
            calendarPanel.add(dayButtons[i]);
        }
        
        // Calendar state
        final int[] currentYear = {cal.get(Calendar.YEAR)};
        final int[] currentMonth = {cal.get(Calendar.MONTH)};
        
        Runnable updateCalendar = () -> {
            Calendar c = Calendar.getInstance();
            c.set(currentYear[0], currentMonth[0], 1);
            
            monthYearLabel.setText(new SimpleDateFormat("MMMM yyyy").format(c.getTime()));
            
            int firstDayOfWeek = c.get(Calendar.DAY_OF_WEEK) - 1;
            int daysInMonth = c.getActualMaximum(Calendar.DAY_OF_MONTH);
            
            for (int i = 0; i < 42; i++) {
                int dayNum = i - firstDayOfWeek + 1;
                if (dayNum >= 1 && dayNum <= daysInMonth) {
                    dayButtons[i].setText(String.valueOf(dayNum));
                    dayButtons[i].setEnabled(true);
                    final int day = dayNum;
                    // Remove old listeners
                    for (var al : dayButtons[i].getActionListeners()) {
                        dayButtons[i].removeActionListener(al);
                    }
                    dayButtons[i].addActionListener(e -> {
                        String selected = String.format("%04d-%02d-%02d", currentYear[0], currentMonth[0] + 1, day);
                        dateField.setText(selected);
                        dialog.dispose();
                    });
                } else {
                    dayButtons[i].setText("");
                    dayButtons[i].setEnabled(false);
                }
            }
        };
        
        prevMonth.addActionListener(e -> {
            currentMonth[0]--;
            if (currentMonth[0] < 0) {
                currentMonth[0] = 11;
                currentYear[0]--;
            }
            updateCalendar.run();
        });
        
        nextMonth.addActionListener(e -> {
            currentMonth[0]++;
            if (currentMonth[0] > 11) {
                currentMonth[0] = 0;
                currentYear[0]++;
            }
            updateCalendar.run();
        });
        
        // Today button
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        JButton todayBtn = new JButton("Today");
        todayBtn.addActionListener(e -> {
            dateField.setText(new SimpleDateFormat("yyyy-MM-dd").format(new Date()));
            dialog.dispose();
        });
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dialog.dispose());
        bottomPanel.add(todayBtn);
        bottomPanel.add(cancelBtn);
        
        updateCalendar.run();
        
        dialog.add(topPanel, BorderLayout.NORTH);
        dialog.add(calendarPanel, BorderLayout.CENTER);
        dialog.add(bottomPanel, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setLocationRelativeTo(window);
        dialog.setVisible(true);
    }
    
    // ============ Audits Refresh ============
    
    public void refreshAudits() {
        if (!tokenManager.hasValidToken()) {
            auditStatusBanner.showInfo("Not authenticated - please test connection first");
            return;
        }
        
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
                        tableModel.setAudits(result.getData());
                        auditStatusBanner.showSuccess("Loaded " + result.getData().size() + " audits");
                        updateButtonStates();
                    } else {
                        auditStatusBanner.showError("Failed to load audits", result.getError());
                    }
                } catch (Exception e) {
                    auditStatusBanner.showError("Failed to load audits", e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    // ============ Polling ============
    
    private void updatePolling() {
        // Cancel existing tasks
        if (pollingTask != null) {
            pollingTask.cancel(false);
            pollingTask = null;
        }
        if (customFieldsPollingTask != null) {
            customFieldsPollingTask.cancel(false);
            customFieldsPollingTask = null;
        }
        
        if (isShuttingDown) return;
        
        if (tokenManager.hasValidToken()) {
            // Audits auto-refresh
            if (configManager.isAutoRefreshAudits()) {
                int interval = configManager.getAuditRefreshIntervalSeconds();
                pollingTask = scheduler.scheduleAtFixedRate(() -> {
                    if (!isShuttingDown && tokenManager.hasValidToken()) {
                        SwingUtilities.invokeLater(this::refreshAuditsQuiet);
                    }
                }, interval, interval, TimeUnit.SECONDS);
            }
            
            // Custom fields periodic refresh (detect new fields)
            customFieldsPollingTask = scheduler.scheduleAtFixedRate(() -> {
                if (!isShuttingDown && tokenManager.hasValidToken()) {
                    refreshCustomFieldsQuiet();
                }
            }, CUSTOM_FIELDS_REFRESH_INTERVAL_SECONDS, CUSTOM_FIELDS_REFRESH_INTERVAL_SECONDS, TimeUnit.SECONDS);
        }
    }
    
    private void refreshCustomFieldsQuiet() {
        ApiResult<List<CustomField>> result = apiClient.getCustomFields();
        if (result.isSuccess()) {
            List<CustomField> newFields = result.getData();
            // Check if fields changed
            if (!customFieldsEqual(customFields, newFields)) {
                customFields = newFields;
                SwingUtilities.invokeLater(() -> {
                    buildCustomFieldsPanel();
                    logging.logToOutput("Custom fields updated - detected " + customFields.size() + " fields");
                });
            }
        }
    }
    
    private boolean customFieldsEqual(List<CustomField> list1, List<CustomField> list2) {
        if (list1.size() != list2.size()) return false;
        for (int i = 0; i < list1.size(); i++) {
            CustomField f1 = list1.get(i);
            CustomField f2 = list2.get(i);
            if (!Objects.equals(f1.id, f2.id) || 
                !Objects.equals(f1.fieldType, f2.fieldType) ||
                !Objects.equals(f1.label, f2.label)) {
                return false;
            }
        }
        return true;
    }
    
    private void refreshAuditsQuiet() {
        if (!tokenManager.hasValidToken()) {
            return;
        }
        
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
                        tableModel.setAudits(result.getData());
                        updateButtonStates();
                    }
                } catch (Exception ignored) {
                    // Silent refresh - don't show errors
                }
            }
        };
        worker.execute();
    }
    
    public void shutdown() {
        isShuttingDown = true;
        if (pollingTask != null) {
            pollingTask.cancel(true);
        }
        if (customFieldsPollingTask != null) {
            customFieldsPollingTask.cancel(true);
        }
        scheduler.shutdownNow();
    }
    
    public Component getComponent() {
        return scrollPane;
    }
    
    // ============ Table Model ============
    
    private class AuditsTableModel extends AbstractTableModel {
        
        private final String[] columns = {"Default", "Audit Name", "Audit Type", "Company", "Participants", "Date", "Approved"};
        private List<Audit> audits = new ArrayList<>();
        
        public void setAudits(List<Audit> audits) {
            this.audits = audits != null ? audits : new ArrayList<>();
            fireTableDataChanged();
        }
        
        public Audit getAuditAt(int row) {
            if (row >= 0 && row < audits.size()) {
                return audits.get(row);
            }
            return null;
        }
        
        @Override
        public int getRowCount() {
            return audits.size();
        }
        
        @Override
        public int getColumnCount() {
            return columns.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columns[column];
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= audits.size()) return null;
            Audit audit = audits.get(rowIndex);
            
            return switch (columnIndex) {
                case 0 -> audit.id.equals(configManager.getDefaultAuditId()) ? "✔" : "";
                case 1 -> audit.name;
                case 2 -> audit.auditType;
                case 3 -> audit.company;
                case 4 -> audit.getParticipantsString();
                case 5 -> audit.dateStart != null ? audit.dateStart : audit.date;
                case 6 -> audit.isApproved() ? "✔" : "";
                default -> null;
            };
        }
    }
    
    // ============ Combo Item ============
    
    private static class ComboItem {
        final String id;
        final String name;
        
        ComboItem(String id, String name) {
            this.id = id;
            this.name = name;
        }
        
        @Override
        public String toString() {
            return name;
        }
    }
}
