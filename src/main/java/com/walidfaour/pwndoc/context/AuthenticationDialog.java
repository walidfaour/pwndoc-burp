/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.context;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.walidfaour.pwndoc.api.ApiResult;
import com.walidfaour.pwndoc.api.PwnDocApiClient;
import com.walidfaour.pwndoc.config.ConfigManager;
import com.walidfaour.pwndoc.ui.components.StatusBanner;
import com.walidfaour.pwndoc.util.TokenManager;

import javax.swing.*;
import java.awt.*;

/**
 * Authentication dialog shown when user triggers context menu action without valid auth.
 */
public class AuthenticationDialog extends JDialog {
    
    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final PwnDocApiClient apiClient;
    private final TokenManager tokenManager;
    private final Logging logging;
    private final Runnable onSuccess;
    
    private JTextField baseUrlField;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JButton authenticateButton;
    private StatusBanner statusBanner;
    
    public AuthenticationDialog(MontoyaApi api, ConfigManager configManager,
                                PwnDocApiClient apiClient, TokenManager tokenManager,
                                Logging logging, Runnable onSuccess) {
        super((Frame) null, "PwnDoc - Authentication Required", true);
        this.api = api;
        this.configManager = configManager;
        this.apiClient = apiClient;
        this.tokenManager = tokenManager;
        this.logging = logging;
        this.onSuccess = onSuccess;
        
        initializeUI();
        loadSavedCredentials();
    }
    
    private void initializeUI() {
        setSize(450, 300);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        
        // Header
        JLabel headerLabel = new JLabel("PwnDoc Authentication");
        headerLabel.setFont(headerLabel.getFont().deriveFont(Font.BOLD, 16f));
        
        JLabel infoLabel = new JLabel("<html>Please enter your PwnDoc credentials to continue.</html>");
        infoLabel.setForeground(Color.GRAY);
        
        JPanel headerPanel = new JPanel(new BorderLayout(5, 5));
        headerPanel.add(headerLabel, BorderLayout.NORTH);
        headerPanel.add(infoLabel, BorderLayout.SOUTH);
        
        // Form
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Base URL
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("PwnDoc Base URL:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        baseUrlField = new JTextField(25);
        baseUrlField.setToolTipText("e.g., https://pwndoc.example.com");
        formPanel.add(baseUrlField, gbc);
        
        // Username
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        usernameField = new JTextField(25);
        formPanel.add(usernameField, gbc);
        
        // Password
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        passwordField = new JPasswordField(25);
        formPanel.add(passwordField, gbc);
        
        // Status banner
        statusBanner = new StatusBanner();
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        formPanel.add(statusBanner, gbc);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        authenticateButton = new JButton("Authenticate");
        authenticateButton.addActionListener(e -> performAuthentication());
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        
        buttonPanel.add(cancelButton);
        buttonPanel.add(authenticateButton);
        
        // Layout
        mainPanel.add(headerPanel, BorderLayout.NORTH);
        mainPanel.add(formPanel, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        setContentPane(mainPanel);
        
        // Enter key triggers auth
        getRootPane().setDefaultButton(authenticateButton);
    }
    
    private void loadSavedCredentials() {
        String savedUrl = configManager.getBaseUrl();
        String savedUsername = configManager.getUsername();
        String savedPassword = configManager.getPassword();
        
        if (savedUrl != null && !savedUrl.isEmpty()) {
            baseUrlField.setText(savedUrl);
        }
        if (savedUsername != null && !savedUsername.isEmpty()) {
            usernameField.setText(savedUsername);
        }
        if (savedPassword != null && !savedPassword.isEmpty()) {
            passwordField.setText(savedPassword);
        }
    }
    
    private void performAuthentication() {
        String baseUrl = baseUrlField.getText().trim();
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        
        // Validate
        if (baseUrl.isEmpty()) {
            statusBanner.showError("Validation Error", "Base URL is required");
            return;
        }
        if (username.isEmpty()) {
            statusBanner.showError("Validation Error", "Username is required");
            return;
        }
        if (password.isEmpty()) {
            statusBanner.showError("Validation Error", "Password is required");
            return;
        }
        
        // Normalize URL
        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
            baseUrl = "https://" + baseUrl;
        }
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        
        // Save credentials to config
        configManager.setBaseUrl(baseUrl);
        configManager.setUsername(username);
        configManager.setPassword(password);
        configManager.saveConfiguration();
        
        // Update UI
        authenticateButton.setEnabled(false);
        statusBanner.showLoading("Authenticating...");
        
        final String finalBaseUrl = baseUrl;
        
        // Perform auth in background
        SwingWorker<ApiResult<String>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<String> doInBackground() {
                return apiClient.testConnection(null);
            }
            
            @Override
            protected void done() {
                try {
                    ApiResult<String> result = get();
                    
                    if (result.isSuccess()) {
                        statusBanner.showSuccess("Authentication successful");
                        logging.logToOutput("Auth dialog: Authentication successful");
                        
                        // Trigger callback and close
                        SwingUtilities.invokeLater(() -> {
                            if (onSuccess != null) {
                                onSuccess.run();
                            }
                            dispose();
                        });
                    } else {
                        String error = result.getError();
                        if ("TOTP_REQUIRED".equals(error)) {
                            // Show TOTP input
                            showTotpInput();
                        } else {
                            statusBanner.showError("Authentication Failed", error);
                            authenticateButton.setEnabled(true);
                        }
                    }
                } catch (Exception e) {
                    statusBanner.showError("Error", e.getMessage());
                    authenticateButton.setEnabled(true);
                }
            }
        };
        worker.execute();
    }
    
    private void showTotpInput() {
        String totp = JOptionPane.showInputDialog(this,
            "Enter TOTP code:",
            "Two-Factor Authentication",
            JOptionPane.QUESTION_MESSAGE);
        
        if (totp != null && !totp.isEmpty()) {
            statusBanner.showLoading("Verifying TOTP...");
            
            SwingWorker<ApiResult<String>, Void> worker = new SwingWorker<>() {
                @Override
                protected ApiResult<String> doInBackground() {
                    return apiClient.testConnection(totp);
                }
                
                @Override
                protected void done() {
                    try {
                        ApiResult<String> result = get();
                        
                        if (result.isSuccess()) {
                            statusBanner.showSuccess("Authentication successful");
                            
                            SwingUtilities.invokeLater(() -> {
                                if (onSuccess != null) {
                                    onSuccess.run();
                                }
                                dispose();
                            });
                        } else {
                            statusBanner.showError("TOTP Failed", result.getError());
                            authenticateButton.setEnabled(true);
                        }
                    } catch (Exception e) {
                        statusBanner.showError("Error", e.getMessage());
                        authenticateButton.setEnabled(true);
                    }
                }
            };
            worker.execute();
        } else {
            authenticateButton.setEnabled(true);
            statusBanner.hide();
        }
    }
}
