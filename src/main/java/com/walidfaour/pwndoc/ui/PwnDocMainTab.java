/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.walidfaour.pwndoc.api.PwnDocApiClient;
import com.walidfaour.pwndoc.config.ConfigManager;
import com.walidfaour.pwndoc.ui.panels.AuditsPanel;
import com.walidfaour.pwndoc.ui.panels.GeneralPanel;
import com.walidfaour.pwndoc.util.TokenManager;

import javax.swing.*;
import java.awt.*;

/**
 * Main tabbed interface for the PwnDoc extension.
 * Contains General and Audits sub-tabs.
 */
public class PwnDocMainTab {
    
    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final PwnDocApiClient apiClient;
    private final TokenManager tokenManager;
    private final Logging logging;
    
    private JPanel mainPanel;
    private JTabbedPane tabbedPane;
    private GeneralPanel generalPanel;
    private AuditsPanel auditsPanel;
    
    public PwnDocMainTab(MontoyaApi api, ConfigManager configManager, 
                         PwnDocApiClient apiClient, TokenManager tokenManager, Logging logging) {
        this.api = api;
        this.configManager = configManager;
        this.apiClient = apiClient;
        this.tokenManager = tokenManager;
        this.logging = logging;
        
        initializeUI();
    }
    
    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        tabbedPane = new JTabbedPane();
        
        // Create sub-tabs
        generalPanel = new GeneralPanel(api, configManager, apiClient, tokenManager, logging, this);
        auditsPanel = new AuditsPanel(api, configManager, apiClient, tokenManager, logging);
        
        // Add tabs in specified order
        tabbedPane.addTab("General", generalPanel.getComponent());
        tabbedPane.addTab("Audits", auditsPanel.getComponent());
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // Set minimum size
        mainPanel.setMinimumSize(new Dimension(600, 400));
        mainPanel.setPreferredSize(new Dimension(900, 700));
    }
    
    /**
     * Returns the main component for registration with Burp.
     */
    public Component getComponent() {
        return mainPanel;
    }
    
    /**
     * Called when authentication succeeds to trigger audit loading.
     */
    public void onAuthenticationSuccess() {
        auditsPanel.onAuthenticationSuccess();
    }
    
    /**
     * Called when authentication fails (wrong credentials, network error, etc.)
     * ISSUE #2 & #6 FIX: Stops polling and clears audit data when auth fails.
     */
    public void onAuthenticationFailure() {
        SwingUtilities.invokeLater(() -> {
            // Stop polling and clear audit data
            if (auditsPanel != null) {
                auditsPanel.onAuthenticationFailure();
            }
        });
    }
    
    /**
     * Called when authentication succeeds from context menu.
     * Refreshes the main tab to reflect authenticated state.
     */
    public void refreshAfterAuth() {
        SwingUtilities.invokeLater(() -> {
            // Refresh general panel to show connected status
            if (generalPanel != null) {
                generalPanel.refreshAuthStatus();
            }
            // Trigger audit loading
            onAuthenticationSuccess();
        });
    }
    
    /**
     * Called when extension is being unloaded.
     */
    public void shutdown() {
        if (auditsPanel != null) {
            auditsPanel.shutdown();
        }
        if (apiClient != null) {
            apiClient.shutdown();
        }
    }
}
