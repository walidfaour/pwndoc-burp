/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.walidfaour.pwndoc.api.PwnDocApiClient;
import com.walidfaour.pwndoc.config.ConfigManager;
import com.walidfaour.pwndoc.context.PwnDocContextMenuProvider;
import com.walidfaour.pwndoc.ui.PwnDocMainTab;
import com.walidfaour.pwndoc.util.TokenManager;

/**
 * Main entry point for the PwnDoc BurpSuite Extension.
 * Implements the Montoya API BurpExtension interface.
 */
public class PwnDocExtension implements BurpExtension {
    
    // ISSUE #1 FIX: Shortened extension name for cleaner context menu path
    // Menu will now be: Extensions → PwnDoc → (actions)
    public static final String EXTENSION_NAME = "PwnDoc";
    public static final String VERSION = "1.0.1";
    
    private MontoyaApi api;
    private Logging logging;
    private ConfigManager configManager;
    private PwnDocApiClient apiClient;
    private TokenManager tokenManager;
    private PwnDocMainTab mainTab;
    private PwnDocContextMenuProvider contextMenuProvider;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        
        // Set extension name
        api.extension().setName(EXTENSION_NAME);
        
        logging.logToOutput("Initializing " + EXTENSION_NAME + " v" + VERSION);
        
        try {
            // Initialize configuration manager
            configManager = new ConfigManager(logging);
            configManager.loadConfiguration();
            
            // Initialize token manager
            tokenManager = new TokenManager(configManager, logging);
            
            // Initialize API client
            apiClient = new PwnDocApiClient(configManager, tokenManager, logging);
            
            // Create and register main tab
            mainTab = new PwnDocMainTab(api, configManager, apiClient, tokenManager, logging);
            api.userInterface().registerSuiteTab("PwnDoc", mainTab.getComponent());
            
            // Register context menu provider for Phase 2 Finding workflows
            contextMenuProvider = new PwnDocContextMenuProvider(
                api, configManager, apiClient, tokenManager, logging,
                () -> {
                    // Callback when auth succeeds from context menu - refresh Phase 1 UI
                    logging.logToOutput("Auth successful from context menu - refreshing main tab");
                    mainTab.refreshAfterAuth();
                }
            );
            api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);
            logging.logToOutput("Registered PwnDoc context menu provider for Proxy/Repeater");
            
            // Register extension unload handler
            api.extension().registerUnloadingHandler(this::onUnload);
            
            logging.logToOutput(EXTENSION_NAME + " initialized successfully");
            
        } catch (Exception e) {
            logging.logToError("Failed to initialize extension: " + e.getMessage());
            throw new RuntimeException("Extension initialization failed", e);
        }
    }
    
    /**
     * Called when extension is being unloaded.
     */
    private void onUnload() {
        logging.logToOutput("Unloading " + EXTENSION_NAME);
        
        // Stop any background tasks
        if (mainTab != null) {
            mainTab.shutdown();
        }
        
        // Clear token
        if (tokenManager != null) {
            tokenManager.clearToken();
        }
        
        // Save configuration
        if (configManager != null) {
            configManager.saveConfiguration();
        }
        
        logging.logToOutput(EXTENSION_NAME + " unloaded");
    }
}
