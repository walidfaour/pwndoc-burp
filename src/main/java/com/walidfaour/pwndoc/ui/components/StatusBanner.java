package com.walidfaour.pwndoc.ui.components;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Inline status banner component for displaying feedback messages.
 * Supports different message types with appropriate styling and optional auto-dismiss.
 */
public class StatusBanner extends JPanel {
    
    /**
     * Status types with associated colors and icons.
     */
    public enum StatusType {
        SUCCESS(new Color(34, 139, 34), new Color(240, 255, 240), "✓"),
        ERROR(new Color(178, 34, 34), new Color(255, 240, 240), "✗"),
        WARNING(new Color(184, 134, 11), new Color(255, 250, 240), "⚠"),
        INFO(new Color(70, 130, 180), new Color(240, 248, 255), "ℹ"),
        LOADING(new Color(100, 100, 100), new Color(248, 248, 248), "⋯");
        
        private final Color textColor;
        private final Color backgroundColor;
        private final String icon;
        
        StatusType(Color textColor, Color backgroundColor, String icon) {
            this.textColor = textColor;
            this.backgroundColor = backgroundColor;
            this.icon = icon;
        }
        
        public Color getTextColor() { return textColor; }
        public Color getBackgroundColor() { return backgroundColor; }
        public String getIcon() { return icon; }
    }
    
    private final JLabel iconLabel;
    private final JLabel messageLabel;
    private final JProgressBar loadingBar;
    private Timer autoDismissTimer;
    private boolean isVisible = false;
    
    /**
     * Creates a new status banner.
     */
    public StatusBanner() {
        setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
        setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 1, 0, new Color(200, 200, 200)),
            new EmptyBorder(8, 12, 8, 12)
        ));
        setAlignmentX(Component.LEFT_ALIGNMENT);
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        
        // Icon label
        iconLabel = new JLabel();
        iconLabel.setFont(iconLabel.getFont().deriveFont(14f));
        iconLabel.setBorder(new EmptyBorder(0, 0, 0, 8));
        
        // Message label
        messageLabel = new JLabel();
        messageLabel.setFont(messageLabel.getFont().deriveFont(12f));
        
        // Loading progress bar (indeterminate)
        loadingBar = new JProgressBar();
        loadingBar.setIndeterminate(true);
        loadingBar.setPreferredSize(new Dimension(80, 16));
        loadingBar.setMaximumSize(new Dimension(80, 16));
        loadingBar.setBorder(new EmptyBorder(0, 10, 0, 0));
        loadingBar.setVisible(false);
        
        add(iconLabel);
        add(messageLabel);
        add(Box.createHorizontalGlue());
        add(loadingBar);
        
        // Initially hidden
        setVisible(false);
    }
    
    /**
     * Shows a status message.
     * 
     * @param type The status type
     * @param message The message to display
     */
    public void show(StatusType type, String message) {
        show(type, message, 0);
    }
    
    /**
     * Shows a status message with optional auto-dismiss.
     * 
     * @param type The status type
     * @param message The message to display
     * @param autoDismissMs Milliseconds before auto-dismiss (0 = no auto-dismiss)
     */
    public void show(StatusType type, String message, int autoDismissMs) {
        cancelAutoDismiss();
        
        SwingUtilities.invokeLater(() -> {
            // Update appearance
            setBackground(type.getBackgroundColor());
            iconLabel.setText(type.getIcon());
            iconLabel.setForeground(type.getTextColor());
            messageLabel.setText(message);
            messageLabel.setForeground(type.getTextColor());
            
            // Show/hide loading bar
            loadingBar.setVisible(type == StatusType.LOADING);
            
            setVisible(true);
            isVisible = true;
            revalidate();
            repaint();
            
            // Schedule auto-dismiss if requested
            if (autoDismissMs > 0) {
                scheduleAutoDismiss(autoDismissMs);
            }
        });
    }
    
    /**
     * Shows a success message.
     * 
     * @param message The message to display
     */
    public void showSuccess(String message) {
        show(StatusType.SUCCESS, message, 5000); // Auto-dismiss after 5s
    }
    
    /**
     * Shows a success message with custom auto-dismiss.
     * 
     * @param message The message to display
     * @param autoDismissMs Milliseconds before auto-dismiss
     */
    public void showSuccess(String message, int autoDismissMs) {
        show(StatusType.SUCCESS, message, autoDismissMs);
    }
    
    /**
     * Shows an error message.
     * 
     * @param message The message to display
     */
    public void showError(String message) {
        show(StatusType.ERROR, message, 0); // Don't auto-dismiss errors
    }
    
    /**
     * Shows an error message with expandable details.
     * 
     * @param message The main message to display
     * @param details Additional details (can be null)
     */
    public void showError(String message, String details) {
        if (details == null || details.isEmpty()) {
            showError(message);
            return;
        }
        
        String fullMessage = message + " [click for details]";
        show(StatusType.ERROR, fullMessage, 0);
        
        // Store details for click handler
        SwingUtilities.invokeLater(() -> {
            // Remove existing listeners
            for (java.awt.event.MouseListener ml : messageLabel.getMouseListeners()) {
                messageLabel.removeMouseListener(ml);
            }
            
            messageLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            messageLabel.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseClicked(java.awt.event.MouseEvent e) {
                    JTextArea textArea = new JTextArea(details);
                    textArea.setEditable(false);
                    textArea.setLineWrap(true);
                    textArea.setWrapStyleWord(true);
                    textArea.setBackground(UIManager.getColor("Panel.background"));
                    
                    JScrollPane scrollPane = new JScrollPane(textArea);
                    scrollPane.setPreferredSize(new Dimension(500, 200));
                    
                    JOptionPane.showMessageDialog(
                        SwingUtilities.getWindowAncestor(StatusBanner.this),
                        scrollPane,
                        "Error Details",
                        JOptionPane.ERROR_MESSAGE
                    );
                }
            });
        });
    }
    
    /**
     * Shows an error message with optional auto-dismiss.
     * 
     * @param message The message to display
     * @param autoDismissMs Milliseconds before auto-dismiss (0 = no auto-dismiss)
     */
    public void showError(String message, int autoDismissMs) {
        show(StatusType.ERROR, message, autoDismissMs);
    }
    
    /**
     * Shows a warning message.
     * 
     * @param message The message to display
     */
    public void showWarning(String message) {
        show(StatusType.WARNING, message, 8000); // Auto-dismiss after 8s
    }
    
    /**
     * Shows an info message.
     * 
     * @param message The message to display
     */
    public void showInfo(String message) {
        show(StatusType.INFO, message, 5000); // Auto-dismiss after 5s
    }
    
    /**
     * Shows a loading message.
     * 
     * @param message The message to display
     */
    public void showLoading(String message) {
        show(StatusType.LOADING, message, 0); // Don't auto-dismiss loading
    }
    
    /**
     * Hides the status banner.
     */
    public void hide() {
        cancelAutoDismiss();
        SwingUtilities.invokeLater(() -> {
            setVisible(false);
            isVisible = false;
            revalidate();
            repaint();
        });
    }
    
    /**
     * Checks if the banner is currently showing.
     * 
     * @return true if visible
     */
    public boolean isShowing() {
        return isVisible;
    }
    
    /**
     * Clears the status banner (alias for hide).
     */
    public void clear() {
        hide();
    }
    
    /**
     * Updates the message text without changing the type.
     * 
     * @param message The new message
     */
    public void updateMessage(String message) {
        SwingUtilities.invokeLater(() -> messageLabel.setText(message));
    }
    
    /**
     * Schedules auto-dismiss of the banner.
     */
    private void scheduleAutoDismiss(int delayMs) {
        autoDismissTimer = new Timer(true);
        autoDismissTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                hide();
            }
        }, delayMs);
    }
    
    /**
     * Cancels any pending auto-dismiss.
     */
    private void cancelAutoDismiss() {
        if (autoDismissTimer != null) {
            autoDismissTimer.cancel();
            autoDismissTimer = null;
        }
    }
    
    /**
     * Transitions from loading to success.
     * 
     * @param message The success message
     */
    public void transitionToSuccess(String message) {
        transitionToSuccess(message, 5000);
    }
    
    /**
     * Transitions from loading to success with custom auto-dismiss.
     * 
     * @param message The success message
     * @param autoDismissMs Milliseconds before auto-dismiss
     */
    public void transitionToSuccess(String message, int autoDismissMs) {
        showSuccess(message, autoDismissMs);
    }
    
    /**
     * Transitions from loading to error.
     * 
     * @param message The error message
     */
    public void transitionToError(String message) {
        showError(message);
    }
    
    /**
     * Creates a compact status banner for use in tight spaces.
     * 
     * @return A compact StatusBanner instance
     */
    public static StatusBanner createCompact() {
        StatusBanner banner = new StatusBanner();
        banner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 1, 0, new Color(200, 200, 200)),
            new EmptyBorder(4, 8, 4, 8)
        ));
        banner.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        banner.messageLabel.setFont(banner.messageLabel.getFont().deriveFont(11f));
        return banner;
    }
}
