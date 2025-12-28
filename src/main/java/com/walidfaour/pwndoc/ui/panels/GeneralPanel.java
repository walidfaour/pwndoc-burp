/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.ui.panels;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.walidfaour.pwndoc.api.ApiResult;
import com.walidfaour.pwndoc.api.PwnDocApiClient;
import com.walidfaour.pwndoc.config.ConfigManager;
import com.walidfaour.pwndoc.ui.PwnDocMainTab;
import com.walidfaour.pwndoc.ui.components.SectionHeader;
import com.walidfaour.pwndoc.ui.components.StatusBanner;
import com.walidfaour.pwndoc.util.TokenManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.Arrays;
import java.util.List;

/**
 * General configuration tab containing all settings sections.
 */
public class GeneralPanel {
    
    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final PwnDocApiClient apiClient;
    private final TokenManager tokenManager;
    private final Logging logging;
    private final PwnDocMainTab mainTab;
    
    private JPanel mainPanel;
    private JScrollPane scrollPane;
    
    // Authentication fields
    private JTextField baseUrlField;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JButton testConnectionButton;
    private StatusBanner authStatusBanner;
    private JPanel totpInputPanel;
    private JTextField totpField;
    
    // Networking fields
    private JCheckBox allowInsecureTlsCheckbox;
    private JSpinner timeoutSpinner;
    private JSpinner maxRetriesSpinner;
    private JComboBox<String> backoffStrategyCombo;
    private JSpinner concurrencySpinner;
    private JSpinner rateLimitSpinner;
    
    // TOTP fields
    private JComboBox<String> totpModeCombo;
    
    // Token fields
    private JCheckBox autoRefreshTokenCheckbox;
    private JSpinner refreshThresholdSpinner;
    private JTextField userAgentField;
    
    // Data handling fields
    private JCheckBox stripCookiesCheckbox;
    private JCheckBox stripAuthHeaderCheckbox;
    private JCheckBox stripJwtCheckbox;
    private JTextArea customRegexArea;
    private JSpinner evidenceSizeSpinner;
    private JSpinner maxImageWidthSpinner;
    private JSlider imageQualitySlider;
    
    // Logging fields
    private JComboBox<String> logLevelCombo;
    private JSpinner logBufferSpinner;
    private JCheckBox fileLoggingCheckbox;
    private JTextField logFilePathField;
    private JButton logFileChooserButton;
    private JCheckBox sanitizeLogsCheckbox;
    
    public GeneralPanel(MontoyaApi api, ConfigManager configManager, 
                        PwnDocApiClient apiClient, TokenManager tokenManager,
                        Logging logging, PwnDocMainTab mainTab) {
        this.api = api;
        this.configManager = configManager;
        this.apiClient = apiClient;
        this.tokenManager = tokenManager;
        this.logging = logging;
        this.mainTab = mainTab;
        
        initializeUI();
        loadSettings();
    }
    
    private void initializeUI() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Add sections in order
        mainPanel.add(createAuthenticationSection());
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(createNetworkingSection());
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(createTotpSection());
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(createTokenSection());
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(createDataHandlingSection());
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(createLoggingSection());
        mainPanel.add(Box.createVerticalStrut(15));
        mainPanel.add(createRestoreDefaultsSection());
        mainPanel.add(Box.createVerticalGlue());
        
        scrollPane = new JScrollPane(mainPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
    }
    
    // ============ Authentication Section ============
    
    private JPanel createAuthenticationSection() {
        JPanel section = new JPanel();
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            new EmptyBorder(10, 10, 10, 10)
        ));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        // Header
        String helpText = """
            Configure connection to your PwnDoc server.
            
            • Base URL: The full URL to your PwnDoc server (e.g., https://pwndoc.example.com)
            • Username: Your PwnDoc username
            • Password: Your PwnDoc password (stored encrypted locally)
            
            Click 'Test Connection' to verify credentials and establish a session.
            """;
        
        SectionHeader header = new SectionHeader("Authentication", helpText,
            () -> configManager.resetAuthenticationDefaults(),
            () -> configManager.saveConfiguration(),
            () -> { configManager.reloadFromDisk(); loadSettings(); }
        );
        section.add(header);
        section.add(Box.createVerticalStrut(10));
        
        // Status banner
        authStatusBanner = new StatusBanner();
        section.add(authStatusBanner);
        section.add(Box.createVerticalStrut(5));
        
        // Form fields
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Base URL
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("PwnDoc Base URL:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        baseUrlField = new JTextField(30);
        baseUrlField.addActionListener(e -> saveAuthSettings());
        formPanel.add(baseUrlField, gbc);
        
        // Username
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        usernameField = new JTextField(30);
        usernameField.addActionListener(e -> saveAuthSettings());
        formPanel.add(usernameField, gbc);
        
        // Password
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        passwordField = new JPasswordField(30);
        passwordField.addActionListener(e -> saveAuthSettings());
        formPanel.add(passwordField, gbc);
        
        // Test Connection button
        gbc.gridx = 1; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        testConnectionButton = new JButton("Test Connection");
        testConnectionButton.addActionListener(e -> testConnection(null));
        formPanel.add(testConnectionButton, gbc);
        
        section.add(formPanel);
        
        // TOTP input panel (hidden by default)
        totpInputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        totpInputPanel.add(new JLabel("TOTP Code:"));
        totpField = new JTextField(8);
        totpInputPanel.add(totpField);
        JButton totpSubmitButton = new JButton("Submit");
        totpSubmitButton.addActionListener(e -> testConnection(totpField.getText()));
        totpInputPanel.add(totpSubmitButton);
        totpInputPanel.setVisible(false);
        totpInputPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        section.add(totpInputPanel);
        
        return section;
    }
    
    private void saveAuthSettings() {
        configManager.setBaseUrl(baseUrlField.getText().trim());
        configManager.setUsername(usernameField.getText().trim());
        configManager.setPassword(new String(passwordField.getPassword()));
    }
    
    private void testConnection(String totpToken) {
        saveAuthSettings();
        testConnectionButton.setEnabled(false);
        authStatusBanner.showLoading("Testing connection...");
        totpInputPanel.setVisible(false);
        
        SwingWorker<ApiResult<String>, Void> worker = new SwingWorker<>() {
            @Override
            protected ApiResult<String> doInBackground() {
                return apiClient.testConnection(totpToken);
            }
            
            @Override
            protected void done() {
                testConnectionButton.setEnabled(true);
                try {
                    ApiResult<String> result = get();
                    if (result.isSuccess()) {
                        authStatusBanner.showSuccess("Connection successful");
                        totpInputPanel.setVisible(false);
                        totpField.setText("");
                        // Notify main tab to load audits
                        mainTab.onAuthenticationSuccess();
                    } else {
                        // ISSUE #2 & #6 FIX: On ANY auth failure, immediately invalidate token
                        // This prevents old tokens from being used after entering wrong credentials
                        tokenManager.clearToken();
                        
                        // Notify main tab to stop polling and clear audit data
                        mainTab.onAuthenticationFailure();
                        
                        if ("TOTP_REQUIRED".equals(result.getError())) {
                            authStatusBanner.showInfo("TOTP required - enter code below");
                            totpInputPanel.setVisible(true);
                            totpField.requestFocus();
                        } else {
                            authStatusBanner.showError("Connection failed", result.getError());
                        }
                    }
                } catch (Exception e) {
                    // ISSUE #2 & #6 FIX: Clear token on exception too
                    tokenManager.clearToken();
                    mainTab.onAuthenticationFailure();
                    authStatusBanner.showError("Connection failed", e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    /**
     * Refreshes the authentication status display.
     * Called when auth succeeds from context menu.
     */
    public void refreshAuthStatus() {
        if (tokenManager.hasValidToken()) {
            authStatusBanner.showSuccess("Connection successful (authenticated via context menu)");
        }
    }
    
    // ============ Networking Section ============
    
    private JPanel createNetworkingSection() {
        JPanel section = new JPanel();
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            new EmptyBorder(10, 10, 10, 10)
        ));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        String helpText = """
            Network connection settings.
            
            • Allow insecure TLS: Accept self-signed certificates (WARNING: reduces security)
            • Request timeout: Maximum time to wait for server response
            • Max retries: Number of retry attempts for failed requests
            • Backoff strategy: How to space out retries
            • Concurrency limit: Maximum simultaneous requests
            • Rate limit: Maximum requests per minute
            """;
        
        SectionHeader header = new SectionHeader("Networking", helpText,
            () -> { configManager.resetNetworkingDefaults(); loadSettings(); },
            () -> configManager.saveConfiguration(),
            () -> { configManager.reloadFromDisk(); loadSettings(); }
        );
        section.add(header);
        section.add(Box.createVerticalStrut(10));
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Allow insecure TLS
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        allowInsecureTlsCheckbox = new JCheckBox("Allow insecure TLS (accept self-signed certificates)");
        allowInsecureTlsCheckbox.setToolTipText("WARNING: Reduces security by accepting any certificate");
        allowInsecureTlsCheckbox.addActionListener(e -> 
            configManager.setAllowInsecureTls(allowInsecureTlsCheckbox.isSelected()));
        formPanel.add(allowInsecureTlsCheckbox, gbc);
        
        // Timeout
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        formPanel.add(new JLabel("Request timeout (seconds):"), gbc);
        gbc.gridx = 1;
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(15, 5, 120, 1));
        timeoutSpinner.addChangeListener(e -> 
            configManager.setTimeoutSeconds((Integer) timeoutSpinner.getValue()));
        formPanel.add(timeoutSpinner, gbc);
        
        // Max retries
        gbc.gridx = 0; gbc.gridy = 2;
        formPanel.add(new JLabel("Max retries:"), gbc);
        gbc.gridx = 1;
        maxRetriesSpinner = new JSpinner(new SpinnerNumberModel(3, 0, 10, 1));
        maxRetriesSpinner.addChangeListener(e -> 
            configManager.setMaxRetries((Integer) maxRetriesSpinner.getValue()));
        formPanel.add(maxRetriesSpinner, gbc);
        
        // Backoff strategy
        gbc.gridx = 0; gbc.gridy = 3;
        formPanel.add(new JLabel("Retry backoff strategy:"), gbc);
        gbc.gridx = 1;
        backoffStrategyCombo = new JComboBox<>(new String[]{"Fixed", "Linear", "Exponential"});
        backoffStrategyCombo.addActionListener(e -> 
            configManager.setRetryBackoffStrategy((String) backoffStrategyCombo.getSelectedItem()));
        formPanel.add(backoffStrategyCombo, gbc);
        
        // Concurrency limit
        gbc.gridx = 0; gbc.gridy = 4;
        formPanel.add(new JLabel("Concurrency limit:"), gbc);
        gbc.gridx = 1;
        concurrencySpinner = new JSpinner(new SpinnerNumberModel(2, 1, 5, 1));
        concurrencySpinner.addChangeListener(e -> {
            configManager.setConcurrencyLimit((Integer) concurrencySpinner.getValue());
            apiClient.updateConcurrencyLimit();
        });
        formPanel.add(concurrencySpinner, gbc);
        
        // Rate limit
        gbc.gridx = 0; gbc.gridy = 5;
        formPanel.add(new JLabel("Rate limit (req/min):"), gbc);
        gbc.gridx = 1;
        rateLimitSpinner = new JSpinner(new SpinnerNumberModel(60, 10, 600, 10));
        rateLimitSpinner.addChangeListener(e -> 
            configManager.setRateLimitPerMinute((Integer) rateLimitSpinner.getValue()));
        formPanel.add(rateLimitSpinner, gbc);
        
        section.add(formPanel);
        return section;
    }
    
    // ============ TOTP Section ============
    
    private JPanel createTotpSection() {
        JPanel section = new JPanel();
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            new EmptyBorder(10, 10, 10, 10)
        ));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        String helpText = """
            TOTP (Time-based One-Time Password) settings.
            
            • Prompt when needed: Only ask for TOTP when server requires it
            • Always prompt: Always ask for TOTP code when connecting
            • Disabled: Never prompt for TOTP (may cause authentication failures)
            """;
        
        SectionHeader header = new SectionHeader("TOTP / MFA", helpText,
            () -> { configManager.resetTotpDefaults(); loadSettings(); },
            () -> configManager.saveConfiguration(),
            () -> { configManager.reloadFromDisk(); loadSettings(); }
        );
        section.add(header);
        section.add(Box.createVerticalStrut(10));
        
        JPanel formPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        formPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        formPanel.add(new JLabel("TOTP Mode:"));
        totpModeCombo = new JComboBox<>(new String[]{
            "Prompt when needed", "Always prompt", "Disabled"
        });
        totpModeCombo.addActionListener(e -> 
            configManager.setTotpMode((String) totpModeCombo.getSelectedItem()));
        formPanel.add(totpModeCombo);
        
        section.add(formPanel);
        return section;
    }
    
    // ============ Token Section ============
    
    private JPanel createTokenSection() {
        JPanel section = new JPanel();
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            new EmptyBorder(10, 10, 10, 10)
        ));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        String helpText = """
            Token and session management settings.
            
            • Auto-refresh token: Automatically refresh token before it expires
            • Refresh threshold: Refresh when TTL drops below this value
            • Custom User-Agent: HTTP User-Agent header value
            """;
        
        SectionHeader header = new SectionHeader("Token / Session", helpText,
            () -> { configManager.resetTokenDefaults(); loadSettings(); },
            () -> configManager.saveConfiguration(),
            () -> { configManager.reloadFromDisk(); loadSettings(); }
        );
        section.add(header);
        section.add(Box.createVerticalStrut(10));
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Auto-refresh
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        autoRefreshTokenCheckbox = new JCheckBox("Auto-refresh token");
        autoRefreshTokenCheckbox.addActionListener(e -> 
            configManager.setAutoRefreshToken(autoRefreshTokenCheckbox.isSelected()));
        formPanel.add(autoRefreshTokenCheckbox, gbc);
        
        // Refresh threshold
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        formPanel.add(new JLabel("Refresh when TTL < (minutes):"), gbc);
        gbc.gridx = 1;
        refreshThresholdSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 30, 1));
        refreshThresholdSpinner.addChangeListener(e -> 
            configManager.setTokenRefreshThresholdMinutes((Integer) refreshThresholdSpinner.getValue()));
        formPanel.add(refreshThresholdSpinner, gbc);
        
        // User-Agent
        gbc.gridx = 0; gbc.gridy = 2;
        formPanel.add(new JLabel("Custom User-Agent:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        userAgentField = new JTextField(30);
        userAgentField.addActionListener(e -> 
            configManager.setCustomUserAgent(userAgentField.getText().trim()));
        userAgentField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent e) {
                configManager.setCustomUserAgent(userAgentField.getText().trim());
            }
        });
        formPanel.add(userAgentField, gbc);
        
        section.add(formPanel);
        return section;
    }
    
    // ============ Data Handling Section ============
    
    private JPanel createDataHandlingSection() {
        JPanel section = new JPanel();
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            new EmptyBorder(10, 10, 10, 10)
        ));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        String helpText = """
            Data redaction and evidence handling settings.
            
            Redaction Rules (for future evidence/finding features):
            • Strip cookies: Remove Cookie headers from captured data
            • Strip Authorization: Remove Authorization headers
            • Strip JWT strings: Remove JWT-like tokens
            • Custom regex: One pattern per line
            
            Evidence Controls:
            • Size cap: Maximum evidence attachment size
            • Image width: Resize images to this maximum width
            • Image quality: JPEG compression quality
            """;
        
        SectionHeader header = new SectionHeader("Data Handling", helpText,
            () -> { configManager.resetDataHandlingDefaults(); loadSettings(); },
            () -> configManager.saveConfiguration(),
            () -> { configManager.reloadFromDisk(); loadSettings(); }
        );
        section.add(header);
        section.add(Box.createVerticalStrut(10));
        
        // Redaction rules
        JPanel redactionPanel = new JPanel();
        redactionPanel.setLayout(new BoxLayout(redactionPanel, BoxLayout.Y_AXIS));
        redactionPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        redactionPanel.setBorder(BorderFactory.createTitledBorder("Redaction Rules"));
        
        stripCookiesCheckbox = new JCheckBox("Strip cookies");
        stripCookiesCheckbox.addActionListener(e -> 
            configManager.setStripCookies(stripCookiesCheckbox.isSelected()));
        redactionPanel.add(stripCookiesCheckbox);
        
        stripAuthHeaderCheckbox = new JCheckBox("Strip Authorization header");
        stripAuthHeaderCheckbox.addActionListener(e -> 
            configManager.setStripAuthorizationHeader(stripAuthHeaderCheckbox.isSelected()));
        redactionPanel.add(stripAuthHeaderCheckbox);
        
        stripJwtCheckbox = new JCheckBox("Strip JWT-like strings");
        stripJwtCheckbox.addActionListener(e -> 
            configManager.setStripJwtStrings(stripJwtCheckbox.isSelected()));
        redactionPanel.add(stripJwtCheckbox);
        
        redactionPanel.add(Box.createVerticalStrut(5));
        redactionPanel.add(new JLabel("Custom regex rules (one per line):"));
        customRegexArea = new JTextArea(3, 30);
        customRegexArea.setLineWrap(true);
        customRegexArea.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent e) {
                String text = customRegexArea.getText();
                List<String> regexes = Arrays.asList(text.split("\\n"));
                configManager.setCustomRedactionRegexes(regexes);
            }
        });
        JScrollPane regexScroll = new JScrollPane(customRegexArea);
        regexScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        redactionPanel.add(regexScroll);
        
        section.add(redactionPanel);
        section.add(Box.createVerticalStrut(10));
        
        // Evidence controls
        JPanel evidencePanel = new JPanel(new GridBagLayout());
        evidencePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        evidencePanel.setBorder(BorderFactory.createTitledBorder("Evidence Controls"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        gbc.gridx = 0; gbc.gridy = 0;
        evidencePanel.add(new JLabel("Evidence size cap (MB):"), gbc);
        gbc.gridx = 1;
        evidenceSizeSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 100, 1));
        evidenceSizeSpinner.addChangeListener(e -> 
            configManager.setEvidenceSizeCapMb((Integer) evidenceSizeSpinner.getValue()));
        evidencePanel.add(evidenceSizeSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1;
        evidencePanel.add(new JLabel("Max image width (px):"), gbc);
        gbc.gridx = 1;
        maxImageWidthSpinner = new JSpinner(new SpinnerNumberModel(1600, 100, 4000, 100));
        maxImageWidthSpinner.addChangeListener(e -> 
            configManager.setMaxImageWidth((Integer) maxImageWidthSpinner.getValue()));
        evidencePanel.add(maxImageWidthSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2;
        evidencePanel.add(new JLabel("Image quality (%):"), gbc);
        gbc.gridx = 1;
        imageQualitySlider = new JSlider(10, 100, 85);
        imageQualitySlider.setMajorTickSpacing(20);
        imageQualitySlider.setMinorTickSpacing(5);
        imageQualitySlider.setPaintTicks(true);
        imageQualitySlider.setPaintLabels(true);
        imageQualitySlider.addChangeListener(e -> {
            if (!imageQualitySlider.getValueIsAdjusting()) {
                configManager.setImageQualityPercent(imageQualitySlider.getValue());
            }
        });
        evidencePanel.add(imageQualitySlider, gbc);
        
        section.add(evidencePanel);
        return section;
    }
    
    // ============ Logging Section ============
    
    private JPanel createLoggingSection() {
        JPanel section = new JPanel();
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            new EmptyBorder(10, 10, 10, 10)
        ));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        String helpText = """
            Logging configuration.
            
            • Log level: Verbosity of log messages
            • Buffer size: Number of log entries to keep in memory
            • File logging: Write logs to a file
            • Sanitize logs: Remove potentially sensitive data from logs
            
            Note: Secrets (passwords, tokens) are NEVER logged regardless of settings.
            """;
        
        SectionHeader header = new SectionHeader("Logging", helpText,
            () -> { configManager.resetLoggingDefaults(); loadSettings(); },
            () -> configManager.saveConfiguration(),
            () -> { configManager.reloadFromDisk(); loadSettings(); }
        );
        section.add(header);
        section.add(Box.createVerticalStrut(10));
        
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Log level
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("Log level:"), gbc);
        gbc.gridx = 1;
        logLevelCombo = new JComboBox<>(new String[]{"ERROR", "WARN", "INFO", "DEBUG", "TRACE"});
        logLevelCombo.addActionListener(e -> 
            configManager.setLogLevel((String) logLevelCombo.getSelectedItem()));
        formPanel.add(logLevelCombo, gbc);
        
        // Buffer size
        gbc.gridx = 0; gbc.gridy = 1;
        formPanel.add(new JLabel("In-UI log buffer size:"), gbc);
        gbc.gridx = 1;
        logBufferSpinner = new JSpinner(new SpinnerNumberModel(500, 100, 10000, 100));
        logBufferSpinner.addChangeListener(e -> 
            configManager.setLogBufferSize((Integer) logBufferSpinner.getValue()));
        formPanel.add(logBufferSpinner, gbc);
        
        // File logging
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        fileLoggingCheckbox = new JCheckBox("Enable file logging");
        fileLoggingCheckbox.addActionListener(e -> {
            boolean enabled = fileLoggingCheckbox.isSelected();
            configManager.setFileLoggingEnabled(enabled);
            logFilePathField.setEnabled(enabled);
            logFileChooserButton.setEnabled(enabled);
        });
        formPanel.add(fileLoggingCheckbox, gbc);
        
        // Log file path
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1;
        formPanel.add(new JLabel("Log file path:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1;
        JPanel pathPanel = new JPanel(new BorderLayout(5, 0));
        logFilePathField = new JTextField(25);
        logFilePathField.setEnabled(false);
        logFilePathField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent e) {
                configManager.setLogFilePath(logFilePathField.getText().trim());
            }
        });
        pathPanel.add(logFilePathField, BorderLayout.CENTER);
        logFileChooserButton = new JButton("Browse...");
        logFileChooserButton.setEnabled(false);
        logFileChooserButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select Log File");
            if (chooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
                logFilePathField.setText(chooser.getSelectedFile().getAbsolutePath());
                configManager.setLogFilePath(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        pathPanel.add(logFileChooserButton, BorderLayout.EAST);
        formPanel.add(pathPanel, gbc);
        
        // Sanitize logs
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        sanitizeLogsCheckbox = new JCheckBox("Sanitize logs (remove URLs, IPs, etc.)");
        sanitizeLogsCheckbox.addActionListener(e -> 
            configManager.setSanitizeLogs(sanitizeLogsCheckbox.isSelected()));
        formPanel.add(sanitizeLogsCheckbox, gbc);
        
        section.add(formPanel);
        return section;
    }
    
    // ============ Restore Defaults Section ============
    
    private JPanel createRestoreDefaultsSection() {
        JPanel section = new JPanel();
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.GRAY),
            new EmptyBorder(10, 10, 10, 10)
        ));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        String helpText = """
            Reset all settings to their default values.
            
            This will:
            • Clear all authentication credentials
            • Reset all network and behavior settings
            • Clear audit selection
            • Overwrite the configuration file
            
            This action cannot be undone.
            """;
        
        SectionHeader header = new SectionHeader("Restore Defaults", helpText, null, null, null);
        section.add(header);
        section.add(Box.createVerticalStrut(10));
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        JButton restoreButton = new JButton("Restore All Defaults");
        restoreButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(
                mainPanel,
                "Are you sure you want to restore all settings to defaults?\n" +
                "This will clear all credentials and cannot be undone.",
                "Confirm Restore Defaults",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );
            if (result == JOptionPane.YES_OPTION) {
                configManager.resetToDefaults();
                loadSettings();
                tokenManager.clearToken();
                JOptionPane.showMessageDialog(
                    mainPanel,
                    "All settings have been restored to defaults.",
                    "Settings Reset",
                    JOptionPane.INFORMATION_MESSAGE
                );
            }
        });
        buttonPanel.add(restoreButton);
        
        // Config file info
        JLabel configPathLabel = new JLabel("Config file: " + configManager.getConfigFilePath());
        configPathLabel.setFont(configPathLabel.getFont().deriveFont(Font.ITALIC, 10f));
        
        section.add(buttonPanel);
        section.add(Box.createVerticalStrut(5));
        section.add(configPathLabel);
        
        return section;
    }
    
    // ============ Load Settings ============
    
    private void loadSettings() {
        // Authentication
        baseUrlField.setText(configManager.getBaseUrl());
        usernameField.setText(configManager.getUsername());
        passwordField.setText(configManager.getPassword());
        
        // Networking
        allowInsecureTlsCheckbox.setSelected(configManager.isAllowInsecureTls());
        timeoutSpinner.setValue(configManager.getTimeoutSeconds());
        maxRetriesSpinner.setValue(configManager.getMaxRetries());
        backoffStrategyCombo.setSelectedItem(configManager.getRetryBackoffStrategy());
        concurrencySpinner.setValue(configManager.getConcurrencyLimit());
        rateLimitSpinner.setValue(configManager.getRateLimitPerMinute());
        
        // TOTP
        totpModeCombo.setSelectedItem(configManager.getTotpMode());
        
        // Token
        autoRefreshTokenCheckbox.setSelected(configManager.isAutoRefreshToken());
        refreshThresholdSpinner.setValue(configManager.getTokenRefreshThresholdMinutes());
        userAgentField.setText(configManager.getCustomUserAgent());
        
        // Data handling
        stripCookiesCheckbox.setSelected(configManager.isStripCookies());
        stripAuthHeaderCheckbox.setSelected(configManager.isStripAuthorizationHeader());
        stripJwtCheckbox.setSelected(configManager.isStripJwtStrings());
        customRegexArea.setText(String.join("\n", configManager.getCustomRedactionRegexes()));
        evidenceSizeSpinner.setValue(configManager.getEvidenceSizeCapMb());
        maxImageWidthSpinner.setValue(configManager.getMaxImageWidth());
        imageQualitySlider.setValue(configManager.getImageQualityPercent());
        
        // Logging
        logLevelCombo.setSelectedItem(configManager.getLogLevel());
        logBufferSpinner.setValue(configManager.getLogBufferSize());
        fileLoggingCheckbox.setSelected(configManager.isFileLoggingEnabled());
        logFilePathField.setText(configManager.getLogFilePath());
        logFilePathField.setEnabled(configManager.isFileLoggingEnabled());
        logFileChooserButton.setEnabled(configManager.isFileLoggingEnabled());
        sanitizeLogsCheckbox.setSelected(configManager.isSanitizeLogs());
    }
    
    public Component getComponent() {
        return scrollPane;
    }
}
