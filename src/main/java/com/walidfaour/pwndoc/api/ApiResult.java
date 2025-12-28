/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.api;

/**
 * Generic result wrapper for API operations.
 * Provides success/failure state with data or error message.
 */
public class ApiResult<T> {
    
    private final boolean success;
    private final T data;
    private final String error;
    
    private ApiResult(boolean success, T data, String error) {
        this.success = success;
        this.data = data;
        this.error = error;
    }
    
    /**
     * Creates a successful result with data.
     */
    public static <T> ApiResult<T> success(T data) {
        return new ApiResult<>(true, data, null);
    }
    
    /**
     * Creates a failure result with error message.
     */
    public static <T> ApiResult<T> failure(String error) {
        return new ApiResult<>(false, null, error);
    }
    
    /**
     * Returns true if the operation was successful.
     */
    public boolean isSuccess() {
        return success;
    }
    
    /**
     * Returns true if the operation failed.
     */
    public boolean isFailure() {
        return !success;
    }
    
    /**
     * Returns the data if successful, null otherwise.
     */
    public T getData() {
        return data;
    }
    
    /**
     * Returns the error message if failed, null otherwise.
     */
    public String getError() {
        return error;
    }
    
    /**
     * Returns the data if successful, or the provided default value.
     */
    public T getOrDefault(T defaultValue) {
        return success ? data : defaultValue;
    }
    
    /**
     * Executes the given action if successful.
     */
    public ApiResult<T> ifSuccess(java.util.function.Consumer<T> action) {
        if (success) {
            action.accept(data);
        }
        return this;
    }
    
    /**
     * Executes the given action if failed.
     */
    public ApiResult<T> ifFailure(java.util.function.Consumer<String> action) {
        if (!success) {
            action.accept(error);
        }
        return this;
    }
}
