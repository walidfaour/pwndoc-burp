/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.context;

import burp.api.montoya.logging.Logging;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.walidfaour.pwndoc.api.ApiResult;
import com.walidfaour.pwndoc.api.PwnDocApiClient;
import com.walidfaour.pwndoc.ui.components.StatusBanner;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Panel for browsing and selecting from the vulnerability library.
 * Provides search and filter functionality with pagination support.
 * 
 * ISSUE #8 FIX: Implements pagination to handle large vulnerability lists
 * that exceed API response size limits (>1MB).
 */
public class FindingLibraryPanel extends JPanel {
    
    private final PwnDocApiClient apiClient;
    private final Logging logging;
    private final Consumer<JsonObject> onSelect;
    
    private JTextField searchField;
    private JComboBox<String> categoryCombo;
    private JComboBox<String> typeCombo;
    private JTable vulnerabilityTable;
    private DefaultTableModel tableModel;
    private TableRowSorter<DefaultTableModel> sorter;
    private JButton addButton;
    private StatusBanner statusBanner;
    
    // ISSUE #8: Pagination controls
    private JButton prevPageButton;
    private JButton nextPageButton;
    private JLabel pageLabel;
    private static final int PAGE_SIZE = 25;
    private int currentPage = 0;
    private int totalPages = 0;
    
    private List<JsonObject> allVulnerabilities = new ArrayList<>();
    private List<JsonObject> filteredVulnerabilities = new ArrayList<>(); // After search/filter
    private List<String> categories = new ArrayList<>();
    private List<String> types = new ArrayList<>();
    private boolean selectionLocked = false;
    
    public FindingLibraryPanel(PwnDocApiClient apiClient, Logging logging, 
                                Consumer<JsonObject> onSelect) {
        this.apiClient = apiClient;
        this.logging = logging;
        this.onSelect = onSelect;
        
        initializeUI();
    }
    
    private void initializeUI() {
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Vulnerability Library"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        
        // Search/filter row
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        
        // Search field
        filterPanel.add(new JLabel("Search:"));
        searchField = new JTextField(20);
        searchField.setToolTipText("Type to filter vulnerabilities (real-time)");
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilters(); }
            public void removeUpdate(DocumentEvent e) { applyFilters(); }
            public void changedUpdate(DocumentEvent e) { applyFilters(); }
        });
        filterPanel.add(searchField);
        
        // Category dropdown
        filterPanel.add(new JLabel("Category:"));
        categoryCombo = new JComboBox<>();
        categoryCombo.addItem("All Categories");
        categoryCombo.setPreferredSize(new Dimension(150, 25));
        categoryCombo.addActionListener(e -> applyFilters());
        filterPanel.add(categoryCombo);
        
        // Type dropdown
        filterPanel.add(new JLabel("Type:"));
        typeCombo = new JComboBox<>();
        typeCombo.addItem("All Types");
        typeCombo.setPreferredSize(new Dimension(180, 25));
        typeCombo.addActionListener(e -> applyFilters());
        filterPanel.add(typeCombo);
        
        // Table
        String[] columns = {"Title", "Category", "Type", "CVSS"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        vulnerabilityTable = new JTable(tableModel);
        vulnerabilityTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        vulnerabilityTable.setAutoCreateRowSorter(true);
        sorter = new TableRowSorter<>(tableModel);
        vulnerabilityTable.setRowSorter(sorter);
        
        // Column widths
        vulnerabilityTable.getColumnModel().getColumn(0).setPreferredWidth(300);
        vulnerabilityTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        vulnerabilityTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        vulnerabilityTable.getColumnModel().getColumn(3).setPreferredWidth(80);
        
        JScrollPane scrollPane = new JScrollPane(vulnerabilityTable);
        
        vulnerabilityTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                addButton.setEnabled(vulnerabilityTable.getSelectedRow() >= 0 && !selectionLocked);
            }
        });
        
        // Status
        statusBanner = new StatusBanner();
        
        // ISSUE #8: Pagination panel
        JPanel paginationPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        
        prevPageButton = new JButton("◄ Previous");
        prevPageButton.setEnabled(false);
        prevPageButton.addActionListener(e -> {
            if (currentPage > 0) {
                currentPage--;
                updateTableDisplay();
            }
        });
        paginationPanel.add(prevPageButton);
        
        pageLabel = new JLabel("Page 0 of 0");
        paginationPanel.add(pageLabel);
        
        nextPageButton = new JButton("Next ►");
        nextPageButton.setEnabled(false);
        nextPageButton.addActionListener(e -> {
            if (currentPage < totalPages - 1) {
                currentPage++;
                updateTableDisplay();
            }
        });
        paginationPanel.add(nextPageButton);
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        addButton = new JButton("Add Finding");
        addButton.setEnabled(false);
        addButton.addActionListener(e -> addSelectedFinding());
        buttonPanel.add(addButton);
        
        // Bottom panel with pagination and add button
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(paginationPanel, BorderLayout.CENTER);
        bottomPanel.add(buttonPanel, BorderLayout.EAST);
        
        // South panel with status and bottom controls
        JPanel southPanel = new JPanel(new BorderLayout());
        southPanel.add(statusBanner, BorderLayout.NORTH);
        southPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        // Layout
        add(filterPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(southPanel, BorderLayout.SOUTH);
    }
    
    /**
     * Loads vulnerabilities from the API.
     * ISSUE #8 FIX: Handles large responses gracefully with pagination display.
     */
    public void loadVulnerabilities() {
        statusBanner.showLoading("Loading vulnerability library...");
        searchField.setEnabled(false);
        categoryCombo.setEnabled(false);
        typeCombo.setEnabled(false);
        prevPageButton.setEnabled(false);
        nextPageButton.setEnabled(false);
        
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            ApiResult<JsonArray> vulnResult;
            ApiResult<List<String>> catResult;
            ApiResult<List<String>> typeResult;
            String errorMessage = null;
            
            @Override
            protected Void doInBackground() {
                try {
                    // Load vulnerabilities
                    vulnResult = apiClient.getVulnerabilities("en");
                    
                    // Load categories
                    catResult = apiClient.getVulnerabilityCategories();
                    
                    // Load types
                    typeResult = apiClient.getVulnerabilityTypes();
                } catch (Exception e) {
                    errorMessage = e.getMessage();
                    logging.logToError("Error loading vulnerabilities: " + e.getMessage());
                }
                
                return null;
            }
            
            @Override
            protected void done() {
                try {
                    if (errorMessage != null) {
                        statusBanner.showError("Error loading vulnerabilities", errorMessage);
                        enableControls();
                        return;
                    }
                    
                    // Populate vulnerabilities
                    if (vulnResult != null && vulnResult.isSuccess()) {
                        allVulnerabilities.clear();
                        
                        JsonArray vulns = vulnResult.getData();
                        for (JsonElement elem : vulns) {
                            if (elem.isJsonObject()) {
                                allVulnerabilities.add(elem.getAsJsonObject());
                            }
                        }
                        
                        // Apply initial filter (show all) and display first page
                        filteredVulnerabilities = new ArrayList<>(allVulnerabilities);
                        currentPage = 0;
                        updatePagination();
                        updateTableDisplay();
                        
                        statusBanner.showSuccess("Loaded " + allVulnerabilities.size() + " vulnerabilities");
                    } else {
                        String error = vulnResult != null ? vulnResult.getError() : "Unknown error";
                        // ISSUE #8: Handle size limit errors gracefully
                        if (error != null && (error.contains("1MB") || error.contains("size") || error.contains("limit"))) {
                            statusBanner.showError("Response too large", 
                                "The vulnerability library is too large. Please use the search filters to narrow results.");
                        } else {
                            statusBanner.showError("Error loading vulnerabilities", error);
                        }
                    }
                    
                    // Populate categories
                    if (catResult != null && catResult.isSuccess()) {
                        categories.clear();
                        categories.addAll(catResult.getData());
                        categoryCombo.removeAllItems();
                        categoryCombo.addItem("All Categories");
                        for (String cat : categories) {
                            categoryCombo.addItem(cat);
                        }
                    }
                    
                    // Populate types
                    if (typeResult != null && typeResult.isSuccess()) {
                        types.clear();
                        types.addAll(typeResult.getData());
                        typeCombo.removeAllItems();
                        typeCombo.addItem("All Types");
                        for (String type : types) {
                            typeCombo.addItem(type);
                        }
                    }
                    
                    enableControls();
                    
                } catch (Exception e) {
                    statusBanner.showError("Error", e.getMessage());
                    enableControls();
                }
            }
        };
        worker.execute();
    }
    
    private void enableControls() {
        searchField.setEnabled(true);
        categoryCombo.setEnabled(true);
        typeCombo.setEnabled(true);
        updatePaginationButtons();
    }
    
    /**
     * Applies search and filter criteria.
     * ISSUE #8 FIX: Filters across full dataset, then paginates results.
     */
    private void applyFilters() {
        if (selectionLocked) return;
        
        String searchText = searchField.getText().toLowerCase().trim();
        String selectedCategory = (String) categoryCombo.getSelectedItem();
        String selectedType = (String) typeCombo.getSelectedItem();
        
        // Filter the full list
        filteredVulnerabilities = new ArrayList<>();
        
        for (JsonObject vuln : allVulnerabilities) {
            String title = getLocalizedDetail(vuln, "title").toLowerCase();
            String category = getJsonString(vuln, "category");
            String type = getLocalizedDetail(vuln, "vulnType");
            
            // Apply search filter
            if (!searchText.isEmpty() && !title.contains(searchText)) {
                continue;
            }
            
            // Apply category filter
            if (selectedCategory != null && !"All Categories".equals(selectedCategory)) {
                if (!selectedCategory.equals(category)) {
                    continue;
                }
            }
            
            // Apply type filter
            if (selectedType != null && !"All Types".equals(selectedType)) {
                if (type == null || !type.toLowerCase().contains(selectedType.toLowerCase())) {
                    continue;
                }
            }
            
            filteredVulnerabilities.add(vuln);
        }
        
        // Reset to first page after filtering
        currentPage = 0;
        updatePagination();
        updateTableDisplay();
    }
    
    /**
     * ISSUE #8 FIX: Updates pagination state based on filtered results.
     */
    private void updatePagination() {
        int totalItems = filteredVulnerabilities.size();
        totalPages = (int) Math.ceil((double) totalItems / PAGE_SIZE);
        if (totalPages == 0) totalPages = 1; // At least 1 page even if empty
        
        if (currentPage >= totalPages) {
            currentPage = totalPages - 1;
        }
        if (currentPage < 0) {
            currentPage = 0;
        }
        
        updatePaginationButtons();
    }
    
    /**
     * ISSUE #8 FIX: Updates pagination button states.
     */
    private void updatePaginationButtons() {
        prevPageButton.setEnabled(currentPage > 0 && !selectionLocked);
        nextPageButton.setEnabled(currentPage < totalPages - 1 && !selectionLocked);
        
        int startItem = currentPage * PAGE_SIZE + 1;
        int endItem = Math.min((currentPage + 1) * PAGE_SIZE, filteredVulnerabilities.size());
        int total = filteredVulnerabilities.size();
        
        if (total == 0) {
            pageLabel.setText("No results");
        } else {
            pageLabel.setText(String.format("Showing %d-%d of %d (Page %d/%d)", 
                startItem, endItem, total, currentPage + 1, totalPages));
        }
    }
    
    /**
     * ISSUE #8 FIX: Updates table to show only current page of results.
     */
    private void updateTableDisplay() {
        tableModel.setRowCount(0);
        
        int startIndex = currentPage * PAGE_SIZE;
        int endIndex = Math.min(startIndex + PAGE_SIZE, filteredVulnerabilities.size());
        
        for (int i = startIndex; i < endIndex; i++) {
            JsonObject vuln = filteredVulnerabilities.get(i);
            
            String title = getLocalizedDetail(vuln, "title");
            String category = getJsonString(vuln, "category");
            String type = getLocalizedDetail(vuln, "vulnType");
            String cvss = getJsonString(vuln, "cvssv3");
            
            tableModel.addRow(new Object[]{title, category, type, cvss});
        }
        
        updatePaginationButtons();
    }
    
    /**
     * Handles Add Finding button click.
     */
    private void addSelectedFinding() {
        int viewRow = vulnerabilityTable.getSelectedRow();
        if (viewRow < 0) return;
        
        int modelRow = vulnerabilityTable.convertRowIndexToModel(viewRow);
        
        // Calculate actual index in filtered list
        int actualIndex = currentPage * PAGE_SIZE + modelRow;
        if (actualIndex < 0 || actualIndex >= filteredVulnerabilities.size()) return;
        
        JsonObject selectedVuln = filteredVulnerabilities.get(actualIndex);
        
        // Lock selection
        selectionLocked = true;
        searchField.setEnabled(false);
        categoryCombo.setEnabled(false);
        typeCombo.setEnabled(false);
        addButton.setEnabled(false);
        vulnerabilityTable.setEnabled(false);
        prevPageButton.setEnabled(false);
        nextPageButton.setEnabled(false);
        
        // Notify callback
        if (onSelect != null) {
            onSelect.accept(selectedVuln);
        }
    }
    
    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        if (!enabled) {
            selectionLocked = true;
            searchField.setEnabled(false);
            categoryCombo.setEnabled(false);
            typeCombo.setEnabled(false);
            addButton.setEnabled(false);
            vulnerabilityTable.setEnabled(false);
            prevPageButton.setEnabled(false);
            nextPageButton.setEnabled(false);
        }
    }
    
    private String getJsonString(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            JsonElement elem = obj.get(key);
            if (elem.isJsonPrimitive()) {
                return elem.getAsString();
            }
        }
        return "";
    }
    
    /**
     * Gets localized detail from vulnerability.
     * PwnDoc can store details as:
     * - "detail": single object with locale-specific fields (from /api/vulnerabilities/{locale})
     * - "details": array of locale-specific entries (from /api/vulnerabilities)
     * 
     * ISSUE #4 FIX: Handle both formats properly.
     */
    private String getLocalizedDetail(JsonObject vuln, String field) {
        // First try "detail" (singular object) - from locale-specific endpoint
        if (vuln.has("detail") && vuln.get("detail").isJsonObject()) {
            JsonObject detail = vuln.getAsJsonObject("detail");
            String value = getJsonString(detail, field);
            if (!value.isEmpty()) {
                return value;
            }
        }
        
        // Then try "details" (array) - from general endpoint
        if (vuln.has("details") && vuln.get("details").isJsonArray()) {
            JsonArray details = vuln.getAsJsonArray("details");
            for (JsonElement elem : details) {
                if (elem.isJsonObject()) {
                    JsonObject detail = elem.getAsJsonObject();
                    String locale = getJsonString(detail, "locale");
                    if ("en".equals(locale) || locale.isEmpty()) {
                        String value = getJsonString(detail, field);
                        if (!value.isEmpty()) {
                            return value;
                        }
                    }
                }
            }
            
            // Fallback to first detail
            if (details.size() > 0 && details.get(0).isJsonObject()) {
                return getJsonString(details.get(0).getAsJsonObject(), field);
            }
        }
        
        // Final fallback: try direct field on vuln object
        return getJsonString(vuln, field);
    }
}
