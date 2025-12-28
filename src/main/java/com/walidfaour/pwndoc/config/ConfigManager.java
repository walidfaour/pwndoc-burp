/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.config;

import burp.api.montoya.logging.Logging;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Manages extension configuration persistence.
 * Stores settings in JSON format at platform-specific locations.
 */
public class ConfigManager {
    
    private final Logging logging;
    private final Gson gson;
    private final Path configPath;
    private ExtensionConfig config;
    
    // Encryption key derivation (simple obfuscation - not cryptographically secure)
    private static final String OBFUSCATION_SALT = "PwnDocBurpExtension2025";
    private static final String OBFUSCATION_KEY = "BurpPwnDocKey";
    
    public ConfigManager(Logging logging) {
        this.logging = logging;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.configPath = getConfigPath();
        this.config = new ExtensionConfig();
    }
    
    /**
     * Gets the platform-specific configuration file path.
     */
    private Path getConfigPath() {
        String os = System.getProperty("os.name").toLowerCase();
        Path basePath;
        
        if (os.contains("win")) {
            // Windows: %APPDATA%\Burp\PwnDoc\config.json
            String appData = System.getenv("APPDATA");
            if (appData == null) {
                appData = System.getProperty("user.home") + "\\AppData\\Roaming";
            }
            basePath = Paths.get(appData, "Burp", "PwnDoc");
        } else if (os.contains("mac")) {
            // macOS: ~/Library/Application Support/Burp/PwnDoc/config.json
            basePath = Paths.get(System.getProperty("user.home"), 
                "Library", "Application Support", "Burp", "PwnDoc");
        } else {
            // Linux: ~/.config/burp/pwndoc/config.json
            basePath = Paths.get(System.getProperty("user.home"), 
                ".config", "burp", "pwndoc");
        }
        
        return basePath.resolve("config.json");
    }
    
    /**
     * Loads configuration from disk.
     */
    public void loadConfiguration() {
        try {
            if (Files.exists(configPath)) {
                String json = Files.readString(configPath, StandardCharsets.UTF_8);
                config = gson.fromJson(json, ExtensionConfig.class);
                if (config == null) {
                    config = new ExtensionConfig();
                }
                logging.logToOutput("Configuration loaded from: " + configPath);
            } else {
                config = new ExtensionConfig();
                logging.logToOutput("No configuration file found, using defaults");
            }
        } catch (IOException | JsonSyntaxException e) {
            logging.logToError("Failed to load configuration: " + e.getMessage());
            config = new ExtensionConfig();
        }
    }
    
    /**
     * Saves configuration to disk.
     */
    public void saveConfiguration() {
        try {
            // Create directories if they don't exist
            Path parentDir = configPath.getParent();
            if (parentDir != null && !Files.exists(parentDir)) {
                Files.createDirectories(parentDir);
            }
            
            String json = gson.toJson(config);
            Files.writeString(configPath, json, StandardCharsets.UTF_8);
            logging.logToOutput("Configuration saved to: " + configPath);
        } catch (IOException e) {
            logging.logToError("Failed to save configuration: " + e.getMessage());
        }
    }
    
    /**
     * Reloads configuration from disk (discards in-memory changes).
     */
    public void reloadFromDisk() {
        loadConfiguration();
    }
    
    /**
     * Returns the configuration file path for display purposes.
     */
    public String getConfigFilePath() {
        return configPath.toString();
    }
    
    // ============ Authentication Settings ============
    
    public String getBaseUrl() {
        return config.baseUrl;
    }
    
    public void setBaseUrl(String baseUrl) {
        config.baseUrl = baseUrl;
        saveConfiguration();
    }
    
    public String getUsername() {
        return config.username;
    }
    
    public void setUsername(String username) {
        config.username = username;
        saveConfiguration();
    }
    
    public String getPassword() {
        if (config.passwordEncrypted == null || config.passwordEncrypted.isEmpty()) {
            return "";
        }
        return deobfuscate(config.passwordEncrypted);
    }
    
    public void setPassword(String password) {
        config.passwordEncrypted = obfuscate(password);
        saveConfiguration();
    }
    
    // ============ Networking Settings ============
    
    public boolean isAllowInsecureTls() {
        return config.tlsAllowInsecure;
    }
    
    public void setAllowInsecureTls(boolean allow) {
        config.tlsAllowInsecure = allow;
        saveConfiguration();
    }
    
    public int getTimeoutSeconds() {
        return config.timeoutSeconds;
    }
    
    public void setTimeoutSeconds(int timeout) {
        config.timeoutSeconds = Math.max(5, Math.min(120, timeout));
        saveConfiguration();
    }
    
    public int getMaxRetries() {
        return config.maxRetries;
    }
    
    public void setMaxRetries(int retries) {
        config.maxRetries = Math.max(0, Math.min(10, retries));
        saveConfiguration();
    }
    
    public String getRetryBackoffStrategy() {
        return config.retryBackoffStrategy;
    }
    
    public void setRetryBackoffStrategy(String strategy) {
        config.retryBackoffStrategy = strategy;
        saveConfiguration();
    }
    
    public int getConcurrencyLimit() {
        return config.concurrencyLimit;
    }
    
    public void setConcurrencyLimit(int limit) {
        config.concurrencyLimit = Math.max(1, Math.min(5, limit));
        saveConfiguration();
    }
    
    public int getRateLimitPerMinute() {
        return config.rateLimitPerMinute;
    }
    
    public void setRateLimitPerMinute(int limit) {
        config.rateLimitPerMinute = Math.max(10, Math.min(600, limit));
        saveConfiguration();
    }
    
    // ============ TOTP Settings ============
    
    public String getTotpMode() {
        return config.totpMode;
    }
    
    public void setTotpMode(String mode) {
        config.totpMode = mode;
        saveConfiguration();
    }
    
    // ============ Token Settings ============
    
    public boolean isAutoRefreshToken() {
        return config.autoRefreshToken;
    }
    
    public void setAutoRefreshToken(boolean autoRefresh) {
        config.autoRefreshToken = autoRefresh;
        saveConfiguration();
    }
    
    public int getTokenRefreshThresholdMinutes() {
        return config.tokenRefreshThresholdMinutes;
    }
    
    public void setTokenRefreshThresholdMinutes(int minutes) {
        config.tokenRefreshThresholdMinutes = Math.max(1, Math.min(30, minutes));
        saveConfiguration();
    }
    
    public String getCustomUserAgent() {
        return config.customUserAgent;
    }
    
    public void setCustomUserAgent(String userAgent) {
        config.customUserAgent = userAgent;
        saveConfiguration();
    }
    
    // ============ Data Handling Settings ============
    
    public boolean isStripCookies() {
        return config.stripCookies;
    }
    
    public void setStripCookies(boolean strip) {
        config.stripCookies = strip;
        saveConfiguration();
    }
    
    public boolean isStripAuthorizationHeader() {
        return config.stripAuthorizationHeader;
    }
    
    public void setStripAuthorizationHeader(boolean strip) {
        config.stripAuthorizationHeader = strip;
        saveConfiguration();
    }
    
    public boolean isStripJwtStrings() {
        return config.stripJwtStrings;
    }
    
    public void setStripJwtStrings(boolean strip) {
        config.stripJwtStrings = strip;
        saveConfiguration();
    }
    
    public List<String> getCustomRedactionRegexes() {
        return config.customRedactionRegexes != null ? 
            config.customRedactionRegexes : new ArrayList<>();
    }
    
    public void setCustomRedactionRegexes(List<String> regexes) {
        config.customRedactionRegexes = regexes;
        saveConfiguration();
    }
    
    public int getEvidenceSizeCapMb() {
        return config.evidenceSizeCapMb;
    }
    
    public void setEvidenceSizeCapMb(int sizeMb) {
        config.evidenceSizeCapMb = Math.max(1, Math.min(100, sizeMb));
        saveConfiguration();
    }
    
    public int getMaxImageWidth() {
        return config.maxImageWidth;
    }
    
    public void setMaxImageWidth(int width) {
        config.maxImageWidth = Math.max(100, Math.min(4000, width));
        saveConfiguration();
    }
    
    public int getImageQualityPercent() {
        return config.imageQualityPercent;
    }
    
    public void setImageQualityPercent(int quality) {
        config.imageQualityPercent = Math.max(10, Math.min(100, quality));
        saveConfiguration();
    }
    
    // ============ Logging Settings ============
    
    public String getLogLevel() {
        return config.logLevel;
    }
    
    public void setLogLevel(String level) {
        config.logLevel = level;
        saveConfiguration();
    }
    
    public int getLogBufferSize() {
        return config.logBufferSize;
    }
    
    public void setLogBufferSize(int size) {
        config.logBufferSize = Math.max(100, Math.min(10000, size));
        saveConfiguration();
    }
    
    public boolean isFileLoggingEnabled() {
        return config.fileLoggingEnabled;
    }
    
    public void setFileLoggingEnabled(boolean enabled) {
        config.fileLoggingEnabled = enabled;
        saveConfiguration();
    }
    
    public String getLogFilePath() {
        return config.logFilePath;
    }
    
    public void setLogFilePath(String path) {
        config.logFilePath = path;
        saveConfiguration();
    }
    
    public boolean isSanitizeLogs() {
        return config.sanitizeLogs;
    }
    
    public void setSanitizeLogs(boolean sanitize) {
        config.sanitizeLogs = sanitize;
        saveConfiguration();
    }
    
    // ============ Audits Settings ============
    
    public String getDefaultAuditId() {
        return config.defaultAuditId;
    }
    
    public void setDefaultAuditId(String auditId) {
        config.defaultAuditId = auditId;
        saveConfiguration();
    }
    
    public String getDefaultAuditName() {
        return config.defaultAuditName;
    }
    
    public void setDefaultAuditName(String auditName) {
        config.defaultAuditName = auditName;
        saveConfiguration();
    }
    
    public String getDefaultAuditType() {
        return config.defaultAuditType;
    }
    
    public void setDefaultAuditType(String auditType) {
        config.defaultAuditType = auditType;
        saveConfiguration();
    }
    
    /**
     * Set all default audit properties at once.
     */
    public void setDefaultAudit(String auditId, String auditName, String auditType) {
        config.defaultAuditId = auditId != null ? auditId : "";
        config.defaultAuditName = auditName != null ? auditName : "";
        config.defaultAuditType = auditType != null ? auditType : "";
        saveConfiguration();
    }
    
    public boolean isAutoRefreshAudits() {
        return config.autoRefreshAudits;
    }
    
    public void setAutoRefreshAudits(boolean autoRefresh) {
        config.autoRefreshAudits = autoRefresh;
        saveConfiguration();
    }
    
    public int getAuditRefreshIntervalSeconds() {
        return config.auditRefreshIntervalSeconds;
    }
    
    public void setAuditRefreshIntervalSeconds(int seconds) {
        config.auditRefreshIntervalSeconds = Math.max(5, Math.min(300, seconds));
        saveConfiguration();
    }
    
    // ============ Defaults Management ============
    
    /**
     * Resets all settings to their default values.
     */
    public void resetToDefaults() {
        config = new ExtensionConfig();
        saveConfiguration();
    }
    
    /**
     * Resets only authentication settings to defaults.
     */
    public void resetAuthenticationDefaults() {
        config.baseUrl = "";
        config.username = "";
        config.passwordEncrypted = "";
        saveConfiguration();
    }
    
    /**
     * Resets only networking settings to defaults.
     */
    public void resetNetworkingDefaults() {
        config.tlsAllowInsecure = true;
        config.timeoutSeconds = 15;
        config.maxRetries = 3;
        config.retryBackoffStrategy = "Exponential";
        config.concurrencyLimit = 2;
        config.rateLimitPerMinute = 60;
        saveConfiguration();
    }
    
    /**
     * Resets only TOTP settings to defaults.
     */
    public void resetTotpDefaults() {
        config.totpMode = "Prompt when needed";
        saveConfiguration();
    }
    
    /**
     * Resets only token settings to defaults.
     */
    public void resetTokenDefaults() {
        config.autoRefreshToken = true;
        config.tokenRefreshThresholdMinutes = 5;
        config.customUserAgent = "Burp-PwnDoc-Extension/1.0";
        saveConfiguration();
    }
    
    /**
     * Resets only data handling settings to defaults.
     */
    public void resetDataHandlingDefaults() {
        config.stripCookies = false;
        config.stripAuthorizationHeader = false;
        config.stripJwtStrings = false;
        config.customRedactionRegexes = new ArrayList<>();
        config.evidenceSizeCapMb = 10;
        config.maxImageWidth = 1600;
        config.imageQualityPercent = 85;
        saveConfiguration();
    }
    
    /**
     * Resets only logging settings to defaults.
     */
    public void resetLoggingDefaults() {
        config.logLevel = "INFO";
        config.logBufferSize = 500;
        config.fileLoggingEnabled = false;
        config.logFilePath = "";
        config.sanitizeLogs = false;
        saveConfiguration();
    }
    
    /**
     * Resets only audit settings to defaults.
     */
    public void resetAuditDefaults() {
        config.defaultAuditId = "";
        config.defaultAuditName = "";
        config.defaultAuditType = "";
        config.autoRefreshAudits = true;
        config.auditRefreshIntervalSeconds = 5;
        saveConfiguration();
    }
    
    // ============ Obfuscation Helpers ============
    
    private String obfuscate(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            return "";
        }
        try {
            byte[] key = deriveKey();
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            logging.logToError("Password obfuscation failed: " + e.getMessage());
            // Fall back to base64 only
            return Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));
        }
    }
    
    private String deobfuscate(String obfuscated) {
        if (obfuscated == null || obfuscated.isEmpty()) {
            return "";
        }
        try {
            byte[] key = deriveKey();
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decoded = Base64.getDecoder().decode(obfuscated);
            byte[] decrypted = cipher.doFinal(decoded);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Try base64 fallback
            try {
                return new String(Base64.getDecoder().decode(obfuscated), StandardCharsets.UTF_8);
            } catch (Exception e2) {
                logging.logToError("Password deobfuscation failed");
                return "";
            }
        }
    }
    
    private byte[] deriveKey() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(OBFUSCATION_KEY.toCharArray(), 
            OBFUSCATION_SALT.getBytes(StandardCharsets.UTF_8), 65536, 128);
        return factory.generateSecret(spec).getEncoded();
    }
    
    /**
     * Internal configuration model class.
     */
    private static class ExtensionConfig {
        // Authentication
        String baseUrl = "";
        String username = "";
        String passwordEncrypted = "";
        
        // Networking
        boolean tlsAllowInsecure = true;
        int timeoutSeconds = 15;
        int maxRetries = 3;
        String retryBackoffStrategy = "Exponential";
        int concurrencyLimit = 2;
        int rateLimitPerMinute = 60;
        
        // TOTP
        String totpMode = "Prompt when needed";
        
        // Token
        boolean autoRefreshToken = true;
        int tokenRefreshThresholdMinutes = 5;
        String customUserAgent = "Burp-PwnDoc-Extension/1.0";
        
        // Data Handling
        boolean stripCookies = false;
        boolean stripAuthorizationHeader = false;
        boolean stripJwtStrings = false;
        List<String> customRedactionRegexes = new ArrayList<>();
        int evidenceSizeCapMb = 10;
        int maxImageWidth = 1600;
        int imageQualityPercent = 85;
        
        // Logging
        String logLevel = "INFO";
        int logBufferSize = 500;
        boolean fileLoggingEnabled = false;
        String logFilePath = "";
        boolean sanitizeLogs = false;
        
        // Audits
        String defaultAuditId = "";
        String defaultAuditName = "";
        String defaultAuditType = "";
        boolean autoRefreshAudits = true;
        int auditRefreshIntervalSeconds = 5;
    }
}
