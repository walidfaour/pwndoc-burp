/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.api;

import burp.api.montoya.logging.Logging;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.walidfaour.pwndoc.config.ConfigManager;
import com.walidfaour.pwndoc.util.TokenManager;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * HTTP client for PwnDoc API communication.
 * Handles authentication, rate limiting, retries, and concurrent requests.
 */
public class PwnDocApiClient {
    
    private final ConfigManager configManager;
    private final TokenManager tokenManager;
    private final Logging logging;
    private final Gson gson;
    
    // Rate limiting
    private final AtomicLong lastRequestTime = new AtomicLong(0);
    private final AtomicInteger requestCount = new AtomicInteger(0);
    private final Object rateLimitLock = new Object();
    
    // Concurrent request semaphore
    private Semaphore concurrencySemaphore;
    
    // Executor for async operations
    private final ExecutorService executor;
    
    // Cookie storage for session management
    private volatile String sessionCookie = null;
    
    public PwnDocApiClient(ConfigManager configManager, TokenManager tokenManager, Logging logging) {
        this.configManager = configManager;
        this.tokenManager = tokenManager;
        this.logging = logging;
        this.gson = new Gson();
        this.executor = Executors.newCachedThreadPool();
        updateConcurrencyLimit();
    }
    
    /**
     * Updates the concurrency semaphore based on config.
     */
    public void updateConcurrencyLimit() {
        this.concurrencySemaphore = new Semaphore(configManager.getConcurrencyLimit());
    }
    
    /**
     * Tests connection to PwnDoc server and authenticates.
     */
    public ApiResult<String> testConnection(String totpToken) {
        String baseUrl = configManager.getBaseUrl();
        String username = configManager.getUsername();
        String password = configManager.getPassword();
        
        if (baseUrl == null || baseUrl.isEmpty()) {
            return ApiResult.failure("Base URL is required");
        }
        if (username == null || username.isEmpty()) {
            return ApiResult.failure("Username is required");
        }
        if (password == null || password.isEmpty()) {
            return ApiResult.failure("Password is required");
        }
        
        // Build auth request
        JsonObject body = new JsonObject();
        body.addProperty("username", username);
        body.addProperty("password", password);
        if (totpToken != null && !totpToken.isEmpty()) {
            body.addProperty("totpToken", totpToken);
        }
        
        ApiResult<JsonObject> result = post("/api/users/token", body, false);
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            if (response.has("datas") && response.get("datas").isJsonObject()) {
                JsonObject datas = response.getAsJsonObject("datas");
                if (datas.has("token")) {
                    String token = datas.get("token").getAsString();
                    tokenManager.setToken(token);
                    return ApiResult.success(token);
                }
            }
            // Check if TOTP is required
            if (response.has("status") && "totprequired".equals(response.get("status").getAsString())) {
                return ApiResult.failure("TOTP_REQUIRED");
            }
            return ApiResult.failure("Invalid response format - no token found");
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Refreshes the authentication token.
     */
    public ApiResult<String> refreshToken() {
        ApiResult<JsonObject> result = get("/api/users/refreshtoken");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            if (response.has("datas") && response.get("datas").isJsonObject()) {
                JsonObject datas = response.getAsJsonObject("datas");
                if (datas.has("token")) {
                    String token = datas.get("token").getAsString();
                    tokenManager.setToken(token);
                    return ApiResult.success(token);
                }
            }
            return ApiResult.failure("Invalid response format");
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets the list of audits.
     */
    public ApiResult<List<Audit>> getAudits() {
        ApiResult<JsonObject> result = get("/api/audits");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            List<Audit> audits = new ArrayList<>();
            
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                JsonArray datasArray = response.getAsJsonArray("datas");
                for (JsonElement elem : datasArray) {
                    if (elem.isJsonObject()) {
                        Audit audit = parseAudit(elem.getAsJsonObject());
                        if (audit != null) {
                            audits.add(audit);
                        }
                    }
                }
            }
            return ApiResult.success(audits);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets detailed audit information.
     */
    public ApiResult<Audit> getAudit(String auditId) {
        ApiResult<JsonObject> result = get("/api/audits/" + auditId);
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            if (response.has("datas") && response.get("datas").isJsonObject()) {
                Audit audit = parseAudit(response.getAsJsonObject("datas"));
                if (audit != null) {
                    return ApiResult.success(audit);
                }
            }
            return ApiResult.failure("Invalid response format");
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Creates a new audit.
     */
    public ApiResult<Audit> createAudit(String name, String auditType, String language) {
        JsonObject body = new JsonObject();
        body.addProperty("name", name);
        body.addProperty("auditType", auditType);
        body.addProperty("language", language);
        
        ApiResult<JsonObject> result = post("/api/audits", body, true);
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            if (response.has("datas") && response.get("datas").isJsonObject()) {
                JsonObject datas = response.getAsJsonObject("datas");
                if (datas.has("audit") && datas.get("audit").isJsonObject()) {
                    Audit audit = parseAudit(datas.getAsJsonObject("audit"));
                    return ApiResult.success(audit);
                }
            }
            return ApiResult.failure("Invalid response format");
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets an audit's general information as raw JSON.
     * Used to retrieve the full customFields structure.
     */
    public ApiResult<JsonObject> getAuditGeneralJson(String auditId) {
        ApiResult<JsonObject> result = get("/api/audits/" + auditId + "/general");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            if (response.has("datas") && response.get("datas").isJsonObject()) {
                return ApiResult.success(response.getAsJsonObject("datas"));
            }
            return ApiResult.failure("Invalid response format");
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Updates an audit's general information.
     */
    public ApiResult<Void> updateAuditGeneral(String auditId, JsonObject updates) {
        ApiResult<JsonObject> result = put("/api/audits/" + auditId + "/general", updates);
        
        if (result.isSuccess()) {
            return ApiResult.success(null);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Deletes an audit.
     */
    public ApiResult<Void> deleteAudit(String auditId) {
        ApiResult<JsonObject> result = delete("/api/audits/" + auditId);
        
        if (result.isSuccess()) {
            return ApiResult.success(null);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Toggles audit approval status.
     */
    public ApiResult<Void> toggleAuditApproval(String auditId) {
        ApiResult<JsonObject> result = put("/api/audits/" + auditId + "/toggleApproval", new JsonObject());
        
        if (result.isSuccess()) {
            return ApiResult.success(null);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Updates audit ready-for-review status.
     */
    public ApiResult<Void> updateReadyForReview(String auditId, boolean state) {
        JsonObject body = new JsonObject();
        body.addProperty("state", state);
        
        ApiResult<JsonObject> result = put("/api/audits/" + auditId + "/updateReadyForReview", body);
        
        if (result.isSuccess()) {
            return ApiResult.success(null);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets audit types.
     */
    public ApiResult<List<AuditType>> getAuditTypes() {
        ApiResult<JsonObject> result = get("/api/data/audit-types");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            List<AuditType> types = new ArrayList<>();
            
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                JsonArray datasArray = response.getAsJsonArray("datas");
                for (JsonElement elem : datasArray) {
                    if (elem.isJsonObject()) {
                        JsonObject obj = elem.getAsJsonObject();
                        AuditType type = new AuditType();
                        type.name = getStringOrNull(obj, "name");
                        if (obj.has("templates") && obj.get("templates").isJsonArray()) {
                            type.templates = new ArrayList<>();
                            for (JsonElement t : obj.getAsJsonArray("templates")) {
                                if (t.isJsonObject()) {
                                    JsonObject tObj = t.getAsJsonObject();
                                    type.templates.add(getStringOrNull(tObj, "_id"));
                                }
                            }
                        }
                        types.add(type);
                    }
                }
            }
            return ApiResult.success(types);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets templates.
     */
    public ApiResult<List<Template>> getTemplates() {
        ApiResult<JsonObject> result = get("/api/templates");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            List<Template> templates = new ArrayList<>();
            
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                JsonArray datasArray = response.getAsJsonArray("datas");
                for (JsonElement elem : datasArray) {
                    if (elem.isJsonObject()) {
                        JsonObject obj = elem.getAsJsonObject();
                        Template template = new Template();
                        template.id = getStringOrNull(obj, "_id");
                        template.name = getStringOrNull(obj, "name");
                        templates.add(template);
                    }
                }
            }
            return ApiResult.success(templates);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets companies.
     */
    public ApiResult<List<Company>> getCompanies() {
        ApiResult<JsonObject> result = get("/api/companies");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            List<Company> companies = new ArrayList<>();
            
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                JsonArray datasArray = response.getAsJsonArray("datas");
                for (JsonElement elem : datasArray) {
                    if (elem.isJsonObject()) {
                        JsonObject obj = elem.getAsJsonObject();
                        Company company = new Company();
                        company.id = getStringOrNull(obj, "_id");
                        company.name = getStringOrNull(obj, "name");
                        company.shortName = getStringOrNull(obj, "shortName");
                        companies.add(company);
                    }
                }
            }
            return ApiResult.success(companies);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets clients.
     */
    public ApiResult<List<Client>> getClients() {
        ApiResult<JsonObject> result = get("/api/clients");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            List<Client> clients = new ArrayList<>();
            
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                JsonArray datasArray = response.getAsJsonArray("datas");
                for (JsonElement elem : datasArray) {
                    if (elem.isJsonObject()) {
                        JsonObject obj = elem.getAsJsonObject();
                        Client client = new Client();
                        client.id = getStringOrNull(obj, "_id");
                        client.email = getStringOrNull(obj, "email");
                        client.firstname = getStringOrNull(obj, "firstname");
                        client.lastname = getStringOrNull(obj, "lastname");
                        client.company = getStringOrNull(obj, "company");
                        clients.add(client);
                    }
                }
            }
            return ApiResult.success(clients);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets reviewers.
     */
    public ApiResult<List<User>> getReviewers() {
        ApiResult<JsonObject> result = get("/api/users/reviewers");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            List<User> reviewers = new ArrayList<>();
            
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                JsonArray datasArray = response.getAsJsonArray("datas");
                for (JsonElement elem : datasArray) {
                    if (elem.isJsonObject()) {
                        JsonObject obj = elem.getAsJsonObject();
                        User user = new User();
                        user.id = getStringOrNull(obj, "_id");
                        user.username = getStringOrNull(obj, "username");
                        user.firstname = getStringOrNull(obj, "firstname");
                        user.lastname = getStringOrNull(obj, "lastname");
                        reviewers.add(user);
                    }
                }
            }
            return ApiResult.success(reviewers);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets custom fields.
     */
    public ApiResult<List<CustomField>> getCustomFields() {
        ApiResult<JsonObject> result = get("/api/data/custom-fields");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            List<CustomField> fields = new ArrayList<>();
            
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                JsonArray datasArray = response.getAsJsonArray("datas");
                for (JsonElement elem : datasArray) {
                    if (elem.isJsonObject()) {
                        JsonObject obj = elem.getAsJsonObject();
                        CustomField field = new CustomField();
                        field.id = getStringOrNull(obj, "_id");
                        field.fieldType = getStringOrNull(obj, "fieldType");
                        field.label = getStringOrNull(obj, "label");
                        field.display = getStringOrNull(obj, "display");
                        field.displaySub = getStringOrNull(obj, "displaySub");
                        field.description = getStringOrNull(obj, "description");
                        field.required = obj.has("required") && obj.get("required").getAsBoolean();
                        
                        // Parse options - can be array of strings OR array of objects with locale/value
                        if (obj.has("options") && obj.get("options").isJsonArray()) {
                            field.options = new ArrayList<>();
                            Set<String> seenValues = new HashSet<>(); // Avoid duplicates from multiple locales
                            for (JsonElement opt : obj.getAsJsonArray("options")) {
                                String optValue = null;
                                if (opt.isJsonPrimitive()) {
                                    // Simple string option
                                    optValue = opt.getAsString();
                                } else if (opt.isJsonObject()) {
                                    // Object with locale and value
                                    JsonObject optObj = opt.getAsJsonObject();
                                    // Prefer "en" locale, but take any value
                                    String locale = getStringOrNull(optObj, "locale");
                                    if ("en".equalsIgnoreCase(locale) || locale == null) {
                                        optValue = getStringOrNull(optObj, "value");
                                    }
                                }
                                if (optValue != null && !optValue.isEmpty() && !seenValues.contains(optValue)) {
                                    field.options.add(optValue);
                                    seenValues.add(optValue);
                                }
                            }
                        }
                        fields.add(field);
                    }
                }
            }
            logging.logToOutput("Loaded " + fields.size() + " custom fields from API");
            return ApiResult.success(fields);
        }
        
        logging.logToError("Failed to load custom fields: " + result.getError());
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets languages.
     */
    public ApiResult<List<Language>> getLanguages() {
        ApiResult<JsonObject> result = get("/api/data/languages");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            List<Language> languages = new ArrayList<>();
            
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                JsonArray datasArray = response.getAsJsonArray("datas");
                for (JsonElement elem : datasArray) {
                    if (elem.isJsonObject()) {
                        JsonObject obj = elem.getAsJsonObject();
                        Language lang = new Language();
                        lang.locale = getStringOrNull(obj, "locale");
                        lang.language = getStringOrNull(obj, "language");
                        languages.add(lang);
                    }
                }
            }
            return ApiResult.success(languages);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    // ============ Vulnerability Library Methods ============
    
    /**
     * Gets vulnerabilities from the library for a specific locale.
     * Swagger: GET /api/vulnerabilities/{locale}
     */
    public ApiResult<JsonArray> getVulnerabilities(String locale) {
        ApiResult<JsonObject> result = get("/api/vulnerabilities/" + (locale != null ? locale : "en"));
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                return ApiResult.success(response.getAsJsonArray("datas"));
            }
            return ApiResult.failure("Invalid response format");
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets vulnerability categories.
     * Swagger: GET /api/data/vulnerability-categories
     */
    public ApiResult<List<String>> getVulnerabilityCategories() {
        ApiResult<JsonObject> result = get("/api/data/vulnerability-categories");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            List<String> categories = new ArrayList<>();
            
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                JsonArray datasArray = response.getAsJsonArray("datas");
                for (JsonElement elem : datasArray) {
                    if (elem.isJsonObject()) {
                        JsonObject obj = elem.getAsJsonObject();
                        String name = getStringOrNull(obj, "name");
                        if (name != null) {
                            categories.add(name);
                        }
                    }
                }
            }
            return ApiResult.success(categories);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets vulnerability types.
     * Swagger: GET /api/data/vulnerability-types
     */
    public ApiResult<List<String>> getVulnerabilityTypes() {
        ApiResult<JsonObject> result = get("/api/data/vulnerability-types");
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            List<String> types = new ArrayList<>();
            
            if (response.has("datas") && response.get("datas").isJsonArray()) {
                JsonArray datasArray = response.getAsJsonArray("datas");
                for (JsonElement elem : datasArray) {
                    if (elem.isJsonObject()) {
                        JsonObject obj = elem.getAsJsonObject();
                        String name = getStringOrNull(obj, "name");
                        if (name != null) {
                            types.add(name);
                        }
                    }
                }
            }
            return ApiResult.success(types);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    // ============ Findings Methods ============
    
    /**
     * Gets all findings for an audit.
     * Swagger: GET /api/audits/{auditId} (findings are included)
     */
    public ApiResult<JsonArray> getAuditFindings(String auditId) {
        ApiResult<JsonObject> result = get("/api/audits/" + auditId);
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            if (response.has("datas") && response.get("datas").isJsonObject()) {
                JsonObject datas = response.getAsJsonObject("datas");
                if (datas.has("findings") && datas.get("findings").isJsonArray()) {
                    return ApiResult.success(datas.getAsJsonArray("findings"));
                }
            }
            // Return empty array if no findings
            return ApiResult.success(new JsonArray());
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets the full audit data as JsonObject (including findings and auditType).
     * Swagger: GET /api/audits/{auditId}
     */
    public ApiResult<JsonObject> getAuditJson(String auditId) {
        ApiResult<JsonObject> result = get("/api/audits/" + auditId);
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            if (response.has("datas") && response.get("datas").isJsonObject()) {
                return ApiResult.success(response.getAsJsonObject("datas"));
            }
            return ApiResult.failure("Invalid response format");
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Creates a new finding in an audit.
     * Swagger: POST /api/audits/{auditId}/findings
     */
    public ApiResult<JsonObject> createFinding(String auditId, JsonObject findingData) {
        ApiResult<JsonObject> result = post("/api/audits/" + auditId + "/findings", findingData, true);
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            if (response.has("datas") && response.get("datas").isJsonObject()) {
                return ApiResult.success(response.getAsJsonObject("datas"));
            }
            return ApiResult.success(response);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Updates an existing finding.
     * Swagger: PUT /api/audits/{auditId}/findings/{findingId}
     */
    public ApiResult<Void> updateFinding(String auditId, String findingId, JsonObject findingData) {
        ApiResult<JsonObject> result = put("/api/audits/" + auditId + "/findings/" + findingId, findingData);
        
        if (result.isSuccess()) {
            return ApiResult.success(null);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Deletes a finding from an audit.
     * Swagger: DELETE /api/audits/{auditId}/findings/{findingId}
     */
    public ApiResult<Void> deleteFinding(String auditId, String findingId) {
        ApiResult<JsonObject> result = delete("/api/audits/" + auditId + "/findings/" + findingId);
        
        if (result.isSuccess()) {
            return ApiResult.success(null);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Gets a specific finding.
     * Swagger: GET /api/audits/{auditId}/findings/{findingId}
     */
    public ApiResult<JsonObject> getFinding(String auditId, String findingId) {
        ApiResult<JsonObject> result = get("/api/audits/" + auditId + "/findings/" + findingId);
        
        if (result.isSuccess()) {
            JsonObject response = result.getData();
            if (response.has("datas") && response.get("datas").isJsonObject()) {
                return ApiResult.success(response.getAsJsonObject("datas"));
            }
            return ApiResult.failure("Invalid response format");
        }
        
        return ApiResult.failure(result.getError());
    }
    
    // ============ Image/Proof Upload Methods ============
    
    /**
     * Uploads an image/proof to an audit.
     * Swagger: POST /api/images/
     */
    public ApiResult<JsonObject> uploadImage(String auditId, String name, String base64Value) {
        JsonObject body = new JsonObject();
        body.addProperty("auditId", auditId);
        body.addProperty("name", name);
        body.addProperty("value", base64Value);
        
        ApiResult<JsonObject> result = post("/api/images/", body, true);
        
        if (result.isSuccess()) {
            return result;
        }
        
        return ApiResult.failure(result.getError());
    }
    
    /**
     * Deletes an image.
     * Swagger: DELETE /api/images/{imageId}
     */
    public ApiResult<Void> deleteImage(String imageId) {
        ApiResult<JsonObject> result = delete("/api/images/" + imageId);
        
        if (result.isSuccess()) {
            return ApiResult.success(null);
        }
        
        return ApiResult.failure(result.getError());
    }
    
    // ============ HTTP Methods ============
    
    private ApiResult<JsonObject> get(String endpoint) {
        return request("GET", endpoint, null, true);
    }
    
    private ApiResult<JsonObject> post(String endpoint, JsonObject body, boolean authenticated) {
        return request("POST", endpoint, body, authenticated);
    }
    
    private ApiResult<JsonObject> put(String endpoint, JsonObject body) {
        return request("PUT", endpoint, body, true);
    }
    
    private ApiResult<JsonObject> delete(String endpoint) {
        return request("DELETE", endpoint, null, true);
    }
    
    private ApiResult<JsonObject> request(String method, String endpoint, JsonObject body, boolean authenticated) {
        // Acquire concurrency permit
        try {
            if (!concurrencySemaphore.tryAcquire(configManager.getTimeoutSeconds(), TimeUnit.SECONDS)) {
                return ApiResult.failure("Request timeout - too many concurrent requests");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ApiResult.failure("Request interrupted");
        }
        
        try {
            // Rate limiting
            enforceRateLimit();
            
            // Retry logic
            int maxRetries = configManager.getMaxRetries();
            Exception lastException = null;
            
            for (int attempt = 0; attempt <= maxRetries; attempt++) {
                try {
                    return executeRequest(method, endpoint, body, authenticated);
                } catch (IOException e) {
                    lastException = e;
                    if (attempt < maxRetries) {
                        long delay = calculateBackoff(attempt);
                        try {
                            Thread.sleep(delay);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            return ApiResult.failure("Request interrupted during retry");
                        }
                    }
                }
            }
            
            return ApiResult.failure("Request failed after " + maxRetries + " retries: " + 
                (lastException != null ? lastException.getMessage() : "Unknown error"));
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ApiResult.failure("Request interrupted");
        } finally {
            concurrencySemaphore.release();
        }
    }
    
    private ApiResult<JsonObject> executeRequest(String method, String endpoint, JsonObject body, boolean authenticated) throws IOException {
        String baseUrl = configManager.getBaseUrl();
        if (baseUrl == null || baseUrl.isEmpty()) {
            return ApiResult.failure("Base URL not configured");
        }
        
        // Normalize URL
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        
        URL url = URI.create(baseUrl + endpoint).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            // Configure TLS if HTTPS
            if (conn instanceof HttpsURLConnection && configManager.isAllowInsecureTls()) {
                configureInsecureTls((HttpsURLConnection) conn);
            }
            
            conn.setRequestMethod(method);
            conn.setConnectTimeout(configManager.getTimeoutSeconds() * 1000);
            conn.setReadTimeout(configManager.getTimeoutSeconds() * 1000);
            
            // Headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", configManager.getCustomUserAgent());
            
            // Authentication header
            if (authenticated) {
                if (tokenManager.hasValidToken()) {
                    String token = tokenManager.getToken();
                    conn.setRequestProperty("Authorization", "JWT " + token);
                    logging.logToOutput("Request to " + endpoint + " with auth token (length: " + token.length() + ")");
                } else {
                    logging.logToOutput("Request to " + endpoint + " - NO VALID TOKEN AVAILABLE");
                }
            }
            
            // Send session cookie if available
            if (sessionCookie != null && !sessionCookie.isEmpty()) {
                conn.setRequestProperty("Cookie", sessionCookie);
                logging.logToOutput("Sending cookie: " + sessionCookie.substring(0, Math.min(50, sessionCookie.length())) + "...");
            }
            
            // Body
            if (body != null && ("POST".equals(method) || "PUT".equals(method))) {
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(body.toString().getBytes(StandardCharsets.UTF_8));
                }
            }
            
            // Read response
            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn);
            
            // Capture cookies from response
            captureCookies(conn);
            
            if (responseCode >= 200 && responseCode < 300) {
                try {
                    JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
                    return ApiResult.success(json);
                } catch (Exception e) {
                    return ApiResult.failure("Invalid JSON response");
                }
            } else {
                String errorMsg = "HTTP " + responseCode;
                try {
                    JsonObject errorJson = JsonParser.parseString(responseBody).getAsJsonObject();
                    if (errorJson.has("datas") && errorJson.get("datas").isJsonPrimitive()) {
                        errorMsg += ": " + errorJson.get("datas").getAsString();
                    }
                } catch (Exception ignored) {
                    if (!responseBody.isEmpty()) {
                        errorMsg += ": " + responseBody.substring(0, Math.min(100, responseBody.length()));
                    }
                }
                return ApiResult.failure(errorMsg);
            }
            
        } finally {
            conn.disconnect();
        }
    }
    
    private String readResponse(HttpURLConnection conn) throws IOException {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            // Try error stream
            if (conn.getErrorStream() != null) {
                reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
            } else {
                return "";
            }
        }
        
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        return response.toString();
    }
    
    private void captureCookies(HttpURLConnection conn) {
        // Get all Set-Cookie headers
        java.util.List<String> cookies = conn.getHeaderFields().get("Set-Cookie");
        if (cookies == null) {
            cookies = conn.getHeaderFields().get("set-cookie");
        }
        
        if (cookies != null && !cookies.isEmpty()) {
            StringBuilder cookieBuilder = new StringBuilder();
            for (String cookie : cookies) {
                // Extract just the cookie name=value part (before the first semicolon)
                String cookieValue = cookie;
                int semicolonIndex = cookie.indexOf(';');
                if (semicolonIndex > 0) {
                    cookieValue = cookie.substring(0, semicolonIndex);
                }
                if (cookieBuilder.length() > 0) {
                    cookieBuilder.append("; ");
                }
                cookieBuilder.append(cookieValue);
            }
            sessionCookie = cookieBuilder.toString();
            logging.logToOutput("Captured cookies: " + sessionCookie.substring(0, Math.min(80, sessionCookie.length())) + "...");
        }
    }
    
    /**
     * Clears stored session data (token and cookies).
     */
    public void clearSession() {
        tokenManager.clearToken();
        sessionCookie = null;
    }
    
    private void configureInsecureTls(HttpsURLConnection conn) {
        try {
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };
            
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new java.security.SecureRandom());
            conn.setSSLSocketFactory(sc.getSocketFactory());
            conn.setHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            logging.logToError("Failed to configure insecure TLS: " + e.getMessage());
        }
    }
    
    private void enforceRateLimit() throws InterruptedException {
        synchronized (rateLimitLock) {
            long now = System.currentTimeMillis();
            long windowStart = now - 60000; // 1 minute window
            
            if (lastRequestTime.get() < windowStart) {
                requestCount.set(0);
            }
            
            int limit = configManager.getRateLimitPerMinute();
            if (requestCount.get() >= limit) {
                // Wait until next window
                long sleepTime = 60000 - (now - lastRequestTime.get());
                if (sleepTime > 0) {
                    Thread.sleep(sleepTime);
                }
                requestCount.set(0);
            }
            
            lastRequestTime.set(System.currentTimeMillis());
            requestCount.incrementAndGet();
        }
    }
    
    private long calculateBackoff(int attempt) {
        String strategy = configManager.getRetryBackoffStrategy();
        long baseDelay = 1000; // 1 second
        
        return switch (strategy) {
            case "Fixed" -> baseDelay;
            case "Linear" -> baseDelay * (attempt + 1);
            case "Exponential" -> (long) (baseDelay * Math.pow(2, attempt));
            default -> baseDelay;
        };
    }
    
    // ============ Helper Methods ============
    
    private Audit parseAudit(JsonObject obj) {
        Audit audit = new Audit();
        audit.id = getStringOrNull(obj, "_id");
        audit.name = getStringOrNull(obj, "name");
        audit.auditType = getStringOrNull(obj, "auditType");
        audit.language = getStringOrNull(obj, "language");
        
        // Company
        if (obj.has("company") && obj.get("company").isJsonObject()) {
            JsonObject companyObj = obj.getAsJsonObject("company");
            audit.company = getStringOrNull(companyObj, "name");
            audit.companyId = getStringOrNull(companyObj, "_id");
        } else if (obj.has("company") && obj.get("company").isJsonPrimitive()) {
            audit.companyId = obj.get("company").getAsString();
        }
        
        // Client
        if (obj.has("client") && obj.get("client").isJsonObject()) {
            JsonObject clientObj = obj.getAsJsonObject("client");
            audit.clientId = getStringOrNull(clientObj, "_id");
            String fname = getStringOrNull(clientObj, "firstname");
            String lname = getStringOrNull(clientObj, "lastname");
            audit.client = ((fname != null ? fname : "") + " " + (lname != null ? lname : "")).trim();
        }
        
        // Template
        if (obj.has("template") && obj.get("template").isJsonObject()) {
            JsonObject templateObj = obj.getAsJsonObject("template");
            audit.templateId = getStringOrNull(templateObj, "_id");
            audit.templateName = getStringOrNull(templateObj, "name");
        }
        
        // Dates
        audit.date = getStringOrNull(obj, "date");
        audit.dateStart = getStringOrNull(obj, "date_start");
        audit.dateEnd = getStringOrNull(obj, "date_end");
        
        // Participants
        if (obj.has("collaborators") && obj.get("collaborators").isJsonArray()) {
            audit.collaborators = new ArrayList<>();
            for (JsonElement elem : obj.getAsJsonArray("collaborators")) {
                if (elem.isJsonObject()) {
                    JsonObject userObj = elem.getAsJsonObject();
                    String username = getStringOrNull(userObj, "username");
                    if (username != null) {
                        audit.collaborators.add(username);
                    }
                }
            }
        }
        
        if (obj.has("reviewers") && obj.get("reviewers").isJsonArray()) {
            audit.reviewers = new ArrayList<>();
            for (JsonElement elem : obj.getAsJsonArray("reviewers")) {
                if (elem.isJsonObject()) {
                    JsonObject userObj = elem.getAsJsonObject();
                    String username = getStringOrNull(userObj, "username");
                    if (username != null) {
                        audit.reviewers.add(username);
                    }
                }
            }
        }
        
        // State
        if (obj.has("state") && obj.get("state").isJsonPrimitive()) {
            audit.state = obj.get("state").getAsString();
        }
        
        // Scope
        if (obj.has("scope") && obj.get("scope").isJsonArray()) {
            audit.scope = new ArrayList<>();
            for (JsonElement elem : obj.getAsJsonArray("scope")) {
                if (elem.isJsonObject()) {
                    JsonObject scopeObj = elem.getAsJsonObject();
                    String scopeName = getStringOrNull(scopeObj, "name");
                    if (scopeName != null) {
                        audit.scope.add(scopeName);
                    }
                } else if (elem.isJsonPrimitive()) {
                    audit.scope.add(elem.getAsString());
                }
            }
        }
        
        return audit;
    }
    
    private String getStringOrNull(JsonObject obj, String key) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            JsonElement elem = obj.get(key);
            if (elem.isJsonPrimitive()) {
                return elem.getAsString();
            }
        }
        return null;
    }
    
    /**
     * Shuts down the executor service.
     */
    public void shutdown() {
        executor.shutdown();
    }
    
    // ============ Data Classes ============
    
    public static class Audit {
        public String id;
        public String name;
        public String auditType;
        public String language;
        public String company;
        public String companyId;
        public String client;
        public String clientId;
        public String templateId;
        public String templateName;
        public String date;
        public String dateStart;
        public String dateEnd;
        public List<String> collaborators;
        public List<String> reviewers;
        public String state;
        public List<String> scope;
        
        public boolean isApproved() {
            return "APPROVED".equalsIgnoreCase(state);
        }
        
        public String getParticipantsString() {
            List<String> all = new ArrayList<>();
            if (collaborators != null) all.addAll(collaborators);
            if (reviewers != null) all.addAll(reviewers);
            return String.join(", ", all);
        }
    }
    
    public static class AuditType {
        public String name;
        public List<String> templates;
    }
    
    public static class Template {
        public String id;
        public String name;
    }
    
    public static class Company {
        public String id;
        public String name;
        public String shortName;
    }
    
    public static class Client {
        public String id;
        public String email;
        public String firstname;
        public String lastname;
        public String company;
        
        public String getDisplayName() {
            return ((firstname != null ? firstname : "") + " " + (lastname != null ? lastname : "")).trim();
        }
    }
    
    public static class User {
        public String id;
        public String username;
        public String firstname;
        public String lastname;
        
        public String getDisplayName() {
            String name = ((firstname != null ? firstname : "") + " " + (lastname != null ? lastname : "")).trim();
            if (name.isEmpty() && username != null) {
                return username;
            }
            return name.isEmpty() ? "Unknown" : name;
        }
    }
    
    public static class CustomField {
        public String id;
        public String fieldType;
        public String label;
        public String display;
        public String displaySub;
        public String description;
        public boolean required;
        public List<String> options;
    }
    
    public static class Language {
        public String locale;
        public String language;
    }
}
