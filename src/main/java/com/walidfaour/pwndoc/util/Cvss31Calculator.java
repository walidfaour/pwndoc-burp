/*
 * PwnDoc BurpSuite Extension
 * Copyright (c) 2025 Walid Faour
 * Licensed under the MIT License
 */

package com.walidfaour.pwndoc.util;

/**
 * CVSS v3.1 Base Score Calculator.
 * Implements the official CVSS v3.1 specification from FIRST.org.
 * Verified against: https://www.first.org/cvss/calculator/3.1
 */
public class Cvss31Calculator {
    
    /**
     * Calculates CVSS v3.1 base score from vector string.
     * @param vector CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
     * @return CvssResult with score and subscores
     */
    public static CvssResult calculate(String vector) {
        if (vector == null || vector.isEmpty()) {
            return new CvssResult(0, 0, 0, "None", "");
        }
        
        // Parse vector
        String av = extractMetric(vector, "AV");
        String ac = extractMetric(vector, "AC");
        String pr = extractMetric(vector, "PR");
        String ui = extractMetric(vector, "UI");
        String s = extractMetric(vector, "S");
        String c = extractMetric(vector, "C");
        String i = extractMetric(vector, "I");
        String a = extractMetric(vector, "A");
        
        return calculate(av, ac, pr, ui, s, c, i, a);
    }
    
    /**
     * Calculates CVSS v3.1 base score from individual metrics.
     * Based on official CVSS v3.1 Specification Document.
     */
    public static CvssResult calculate(String av, String ac, String pr, String ui, 
                                        String s, String c, String i, String a) {
        // Validate inputs - all must be non-null
        if (av == null || ac == null || pr == null || ui == null || 
            s == null || c == null || i == null || a == null) {
            return new CvssResult(0, 0, 0, "None", "");
        }
        
        // Get numeric metric values per CVSS 3.1 spec
        double avVal = getAttackVectorValue(av);
        double acVal = getAttackComplexityValue(ac);
        double prVal = getPrivilegesRequiredValue(pr, s);
        double uiVal = getUserInteractionValue(ui);
        double cVal = getImpactMetricValue(c);
        double iVal = getImpactMetricValue(i);
        double aVal = getImpactMetricValue(a);
        
        // Step 1: Calculate Impact Sub-Score (ISS)
        // ISS = 1 - [(1 - Confidentiality) × (1 - Integrity) × (1 - Availability)]
        double iss = 1.0 - ((1.0 - cVal) * (1.0 - iVal) * (1.0 - aVal));
        
        // Step 2: Calculate Impact
        double impact;
        boolean scopeChanged = "C".equals(s);
        
        if (scopeChanged) {
            // Scope Changed: 7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15
            impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
        } else {
            // Scope Unchanged: 6.42 × ISS
            impact = 6.42 * iss;
        }
        
        // Step 3: Calculate Exploitability
        // Exploitability = 8.22 × AttackVector × AttackComplexity × PrivilegesRequired × UserInteraction
        double exploitability = 8.22 * avVal * acVal * prVal * uiVal;
        
        // Step 4: Calculate Base Score
        double baseScore;
        if (impact <= 0) {
            baseScore = 0;
        } else {
            if (scopeChanged) {
                // Scope Changed: Roundup(Min[(1.08 × (Impact + Exploitability)), 10])
                baseScore = roundUp(Math.min(1.08 * (impact + exploitability), 10.0));
            } else {
                // Scope Unchanged: Roundup(Min[(Impact + Exploitability), 10])
                baseScore = roundUp(Math.min(impact + exploitability, 10.0));
            }
        }
        
        // Determine severity rating per CVSS 3.1 spec
        String severity = getSeverityRating(baseScore);
        
        // Build vector string
        String vectorString = String.format("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
                                           av, ac, pr, ui, s, c, i, a);
        
        return new CvssResult(baseScore, impact, exploitability, severity, vectorString);
    }
    
    private static String extractMetric(String vector, String metric) {
        // Search for /METRIC: to avoid matching AC when looking for C, UI when looking for I, etc.
        String prefix = "/" + metric + ":";
        int idx = vector.indexOf(prefix);
        if (idx == -1) return null;
        
        int start = idx + prefix.length();
        int end = vector.indexOf("/", start);
        if (end == -1) end = vector.length();
        
        return vector.substring(start, end);
    }
    
    /**
     * Attack Vector (AV) values per CVSS 3.1 spec
     */
    private static double getAttackVectorValue(String av) {
        return switch (av) {
            case "N" -> 0.85;  // Network
            case "A" -> 0.62;  // Adjacent
            case "L" -> 0.55;  // Local
            case "P" -> 0.20;  // Physical
            default -> 0.85;
        };
    }
    
    /**
     * Attack Complexity (AC) values per CVSS 3.1 spec
     */
    private static double getAttackComplexityValue(String ac) {
        return switch (ac) {
            case "L" -> 0.77;  // Low
            case "H" -> 0.44;  // High
            default -> 0.77;
        };
    }
    
    /**
     * Privileges Required (PR) values per CVSS 3.1 spec
     * Note: Values differ based on Scope
     */
    private static double getPrivilegesRequiredValue(String pr, String scope) {
        boolean scopeChanged = "C".equals(scope);
        return switch (pr) {
            case "N" -> 0.85;                      // None (same for both)
            case "L" -> scopeChanged ? 0.68 : 0.62; // Low
            case "H" -> scopeChanged ? 0.50 : 0.27; // High
            default -> 0.85;
        };
    }
    
    /**
     * User Interaction (UI) values per CVSS 3.1 spec
     */
    private static double getUserInteractionValue(String ui) {
        return switch (ui) {
            case "N" -> 0.85;  // None
            case "R" -> 0.62;  // Required
            default -> 0.85;
        };
    }
    
    /**
     * Impact metric (C/I/A) values per CVSS 3.1 spec
     */
    private static double getImpactMetricValue(String impact) {
        return switch (impact) {
            case "H" -> 0.56;  // High
            case "L" -> 0.22;  // Low
            case "N" -> 0.0;   // None
            default -> 0.0;
        };
    }
    
    /**
     * CVSS 3.1 Roundup function per spec:
     * "Roundup returns the smallest number, specified to one decimal place,
     * that is equal to or higher than its input."
     */
    private static double roundUp(double value) {
        // Multiply by 10, ceiling, divide by 10
        return Math.ceil(value * 10.0) / 10.0;
    }
    
    /**
     * Severity rating per CVSS 3.1 spec
     */
    public static String getSeverityRating(double score) {
        if (score == 0.0) return "None";
        if (score <= 3.9) return "Low";
        if (score <= 6.9) return "Medium";
        if (score <= 8.9) return "High";
        return "Critical";
    }
    
    /**
     * Result class containing CVSS scores and metadata.
     */
    public static class CvssResult {
        public final double baseScore;
        public final double impactSubscore;
        public final double exploitabilitySubscore;
        public final String severity;
        public final String vectorString;
        
        public CvssResult(double baseScore, double impactSubscore, 
                         double exploitabilitySubscore, String severity, String vectorString) {
            // Round to 1 decimal place for display
            this.baseScore = Math.round(baseScore * 10.0) / 10.0;
            this.impactSubscore = Math.round(impactSubscore * 10.0) / 10.0;
            this.exploitabilitySubscore = Math.round(exploitabilitySubscore * 10.0) / 10.0;
            this.severity = severity;
            this.vectorString = vectorString;
        }
    }
}
