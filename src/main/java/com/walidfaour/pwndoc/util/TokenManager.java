/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.util;

import burp.api.montoya.logging.Logging;
import com.walidfaour.pwndoc.config.ConfigManager;

import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Manages authentication tokens for the PwnDoc API.
 * Thread-safe token storage and TTL monitoring.
 */
public class TokenManager {
    
    private final ConfigManager configManager;
    private final Logging logging;
    private final ReadWriteLock tokenLock = new ReentrantReadWriteLock();
    private final AtomicReference<String> token = new AtomicReference<>(null);
    private volatile Instant tokenExpiry = null;
    
    public TokenManager(ConfigManager configManager, Logging logging) {
        this.configManager = configManager;
        this.logging = logging;
    }
    
    /**
     * Sets the authentication token.
     */
    public void setToken(String newToken) {
        tokenLock.writeLock().lock();
        try {
            this.token.set(newToken);
            if (newToken != null && !newToken.isEmpty()) {
                this.tokenExpiry = extractExpiry(newToken);
                logging.logToOutput("Token set successfully, length: " + newToken.length() + 
                    ", expiry: " + (tokenExpiry != null ? tokenExpiry.toString() : "unknown"));
            } else {
                this.tokenExpiry = null;
                logging.logToOutput("Token cleared");
            }
        } finally {
            tokenLock.writeLock().unlock();
        }
    }
    
    /**
     * Gets the current authentication token.
     */
    public String getToken() {
        tokenLock.readLock().lock();
        try {
            return token.get();
        } finally {
            tokenLock.readLock().unlock();
        }
    }
    
    /**
     * Clears the current token.
     */
    public void clearToken() {
        setToken(null);
    }
    
    /**
     * Checks if a valid token is present.
     */
    public boolean hasValidToken() {
        tokenLock.readLock().lock();
        try {
            String currentToken = token.get();
            if (currentToken == null || currentToken.isEmpty()) {
                logging.logToOutput("hasValidToken: false - token is null/empty");
                return false;
            }
            if (tokenExpiry != null && Instant.now().isAfter(tokenExpiry)) {
                logging.logToOutput("hasValidToken: false - token expired at " + tokenExpiry);
                return false;
            }
            logging.logToOutput("hasValidToken: true - token length: " + currentToken.length());
            return true;
        } finally {
            tokenLock.readLock().unlock();
        }
    }
    
    /**
     * Checks if the token needs refresh based on configured threshold.
     */
    public boolean needsRefresh() {
        tokenLock.readLock().lock();
        try {
            if (!hasValidToken()) {
                return true;
            }
            if (tokenExpiry == null) {
                return false;
            }
            int thresholdMinutes = configManager.getTokenRefreshThresholdMinutes();
            Instant refreshThreshold = Instant.now().plusSeconds(thresholdMinutes * 60L);
            return tokenExpiry.isBefore(refreshThreshold);
        } finally {
            tokenLock.readLock().unlock();
        }
    }
    
    /**
     * Gets the token expiry time.
     */
    public Instant getExpiry() {
        tokenLock.readLock().lock();
        try {
            return tokenExpiry;
        } finally {
            tokenLock.readLock().unlock();
        }
    }
    
    /**
     * Gets the remaining TTL in seconds.
     */
    public long getRemainingTtlSeconds() {
        tokenLock.readLock().lock();
        try {
            if (tokenExpiry == null) {
                return -1;
            }
            long remaining = tokenExpiry.getEpochSecond() - Instant.now().getEpochSecond();
            return Math.max(0, remaining);
        } finally {
            tokenLock.readLock().unlock();
        }
    }
    
    /**
     * Extracts expiry time from JWT token.
     */
    private Instant extractExpiry(String jwtToken) {
        try {
            String[] parts = jwtToken.split("\\.");
            if (parts.length != 3) {
                return null;
            }
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            // Simple JSON parsing for "exp" field
            int expIndex = payload.indexOf("\"exp\"");
            if (expIndex == -1) {
                return null;
            }
            int colonIndex = payload.indexOf(":", expIndex);
            if (colonIndex == -1) {
                return null;
            }
            int start = colonIndex + 1;
            while (start < payload.length() && !Character.isDigit(payload.charAt(start))) {
                start++;
            }
            int end = start;
            while (end < payload.length() && Character.isDigit(payload.charAt(end))) {
                end++;
            }
            if (start < end) {
                long expSeconds = Long.parseLong(payload.substring(start, end));
                return Instant.ofEpochSecond(expSeconds);
            }
        } catch (Exception e) {
            logging.logToError("Failed to parse JWT expiry: " + e.getMessage());
        }
        return null;
    }
}
