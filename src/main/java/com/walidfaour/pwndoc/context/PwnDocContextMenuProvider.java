/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.context;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.walidfaour.pwndoc.api.PwnDocApiClient;
import com.walidfaour.pwndoc.config.ConfigManager;
import com.walidfaour.pwndoc.util.TokenManager;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides PwnDoc context menu items for Proxy and Repeater.
 * Implements Montoya ContextMenuItemsProvider.
 */
public class PwnDocContextMenuProvider implements ContextMenuItemsProvider {
    
    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final PwnDocApiClient apiClient;
    private final TokenManager tokenManager;
    private final Logging logging;
    private final Runnable onAuthSuccess;
    
    public PwnDocContextMenuProvider(MontoyaApi api, ConfigManager configManager,
                                     PwnDocApiClient apiClient, TokenManager tokenManager,
                                     Logging logging, Runnable onAuthSuccess) {
        this.api = api;
        this.configManager = configManager;
        this.apiClient = apiClient;
        this.tokenManager = tokenManager;
        this.logging = logging;
        this.onAuthSuccess = onAuthSuccess;
    }
    
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        
        // Get request/response context for pre-filling
        HttpRequestResponse requestResponse = null;
        if (event.messageEditorRequestResponse().isPresent()) {
            requestResponse = event.messageEditorRequestResponse().get().requestResponse();
        } else if (!event.selectedRequestResponses().isEmpty()) {
            requestResponse = event.selectedRequestResponses().get(0);
        }
        
        final HttpRequestResponse finalRequestResponse = requestResponse;
        
        // ISSUE #1 FIX: Return menu items directly without wrapping in a JMenu.
        // This results in: Extensions → PwnDoc → Create Finding
        // Instead of: Extensions → PwnDoc BurpSuite Extension → PwnDoc → Create Finding
        
        // Create Finding
        JMenuItem createFinding = new JMenuItem("Create Finding");
        createFinding.addActionListener(e -> {
            SwingUtilities.invokeLater(() -> handleCreateFinding(finalRequestResponse));
        });
        menuItems.add(createFinding);
        
        // Update Finding
        JMenuItem updateFinding = new JMenuItem("Update Finding");
        updateFinding.addActionListener(e -> {
            SwingUtilities.invokeLater(() -> handleUpdateFinding(finalRequestResponse));
        });
        menuItems.add(updateFinding);
        
        // Delete Finding
        JMenuItem deleteFinding = new JMenuItem("Delete Finding");
        deleteFinding.addActionListener(e -> {
            SwingUtilities.invokeLater(() -> handleDeleteFinding());
        });
        menuItems.add(deleteFinding);
        
        return menuItems;
    }
    
    /**
     * Handles Create Finding action.
     */
    private void handleCreateFinding(HttpRequestResponse requestResponse) {
        logging.logToOutput("Context menu: Create Finding clicked");
        
        // Extract context from request for pre-fill
        RequestContext context = extractContext(requestResponse);
        
        // Show workflow window
        showFindingWorkflowWindow("create", null, context);
    }
    
    /**
     * Handles Update Finding action.
     */
    private void handleUpdateFinding(HttpRequestResponse requestResponse) {
        logging.logToOutput("Context menu: Update Finding clicked");
        
        RequestContext context = extractContext(requestResponse);
        showFindingWorkflowWindow("update", null, context);
    }
    
    /**
     * Handles Delete Finding action.
     */
    private void handleDeleteFinding() {
        logging.logToOutput("Context menu: Delete Finding clicked");
        showFindingWorkflowWindow("delete", null, null);
    }
    
    /**
     * Shows the finding workflow window after auth/audit checks.
     */
    private void showFindingWorkflowWindow(String mode, String findingId, RequestContext context) {
        // STEP A: Auth Check
        if (!tokenManager.hasValidToken()) {
            logging.logToOutput("No valid token - showing auth dialog");
            showAuthDialog(() -> {
                // After successful auth, continue to audit check
                checkDefaultAuditAndShowWindow(mode, findingId, context);
            });
            return;
        }
        
        // Already authenticated, check default audit
        checkDefaultAuditAndShowWindow(mode, findingId, context);
    }
    
    /**
     * STEP B: Check default audit and show window.
     */
    private void checkDefaultAuditAndShowWindow(String mode, String findingId, RequestContext context) {
        String defaultAuditId = configManager.getDefaultAuditId();
        
        // Create and show the workflow window
        FindingWorkflowWindow window = new FindingWorkflowWindow(
            api, configManager, apiClient, tokenManager, logging,
            mode, findingId, context, defaultAuditId == null || defaultAuditId.isEmpty()
        );
        window.setVisible(true);
    }
    
    /**
     * Shows authentication dialog.
     */
    private void showAuthDialog(Runnable onSuccess) {
        AuthenticationDialog dialog = new AuthenticationDialog(
            api, configManager, apiClient, tokenManager, logging,
            () -> {
                // Trigger Phase 1 refresh
                if (onAuthSuccess != null) {
                    onAuthSuccess.run();
                }
                onSuccess.run();
            }
        );
        dialog.setVisible(true);
    }
    
    /**
     * Extracts context from HTTP request/response for pre-filling.
     * ISSUE #7 FIX: Truncates very long URLs to scheme + domain only.
     */
    private RequestContext extractContext(HttpRequestResponse requestResponse) {
        RequestContext context = new RequestContext();
        
        if (requestResponse == null || requestResponse.request() == null) {
            return context;
        }
        
        try {
            var request = requestResponse.request();
            context.url = request.url();
            context.host = request.httpService().host();
            context.path = request.path();
            context.method = request.method();
            
            // ISSUE #7: Calculate if URL is "very long" and needs truncation
            // A URL is considered "very long" if it would exceed approximately 100 characters
            // which typically corresponds to 2+ lines in most UI text fields
            if (context.url != null && context.url.length() > 100) {
                try {
                    URI uri = URI.create(context.url);
                    // Use only scheme + host (no path/query) for very long URLs
                    context.truncatedUrl = uri.getScheme() + "://" + uri.getHost();
                    if (uri.getPort() != -1 && uri.getPort() != 80 && uri.getPort() != 443) {
                        context.truncatedUrl += ":" + uri.getPort();
                    }
                } catch (Exception e) {
                    // If URI parsing fails, use host only
                    context.truncatedUrl = context.host;
                }
            }
            
            // Get selected text if available (useful for POC)
            // Note: Selection handling depends on context
            
        } catch (Exception e) {
            logging.logToError("Error extracting request context: " + e.getMessage());
        }
        
        return context;
    }
    
    /**
     * Context extracted from HTTP request for pre-filling finding fields.
     */
    public static class RequestContext {
        public String url;
        public String host;
        public String path;
        public String method;
        public String selectedText;
        public String truncatedUrl; // ISSUE #7: For very long URLs
        
        /**
         * Gets the affected asset string for the finding.
         * ISSUE #7 FIX: Returns truncated URL if original is very long.
         */
        public String getAffectedAsset() {
            // If URL was truncated due to length, use truncated version
            if (truncatedUrl != null && !truncatedUrl.isEmpty()) {
                return truncatedUrl;
            }
            
            if (url != null && !url.isEmpty()) {
                return url;
            }
            if (host != null) {
                return host + (path != null ? path : "");
            }
            return "";
        }
    }
}
