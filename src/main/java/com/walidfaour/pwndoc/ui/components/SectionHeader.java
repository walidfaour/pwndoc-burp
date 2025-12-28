package com.walidfaour.pwndoc.ui.components;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

/**
 * Reusable section header component with title, help icon, and gear menu.
 * Provides consistent styling and behavior across all configuration sections.
 */
public class SectionHeader extends JPanel {
    
    private final JLabel titleLabel;
    private final JLabel helpIcon;
    private final JLabel gearIcon;
    private final JPopupMenu gearMenu;
    private String helpText;
    
    /**
     * Creates a section header with the given title.
     * 
     * @param title The section title to display
     */
    public SectionHeader(String title) {
        this(title, null);
    }
    
    /**
     * Creates a section header with title and help text.
     * 
     * @param title The section title to display
     * @param helpText The help text shown on hover (can be null)
     */
    public SectionHeader(String title, String helpText) {
        this(title, helpText, null, null, null);
    }
    
    /**
     * Creates a section header with title, help text, and gear menu actions.
     * 
     * @param title The section title to display
     * @param helpText The help text shown on hover (can be null)
     * @param onRestoreDefaults Action for restore defaults (can be null)
     * @param onSave Action for save settings (can be null)
     * @param onReload Action for reload from disk (can be null)
     */
    public SectionHeader(String title, String helpText, 
                         Runnable onRestoreDefaults, 
                         Runnable onSave, 
                         Runnable onReload) {
        this.helpText = helpText;
        
        setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
        setBorder(new EmptyBorder(8, 0, 4, 0));
        setAlignmentX(Component.LEFT_ALIGNMENT);
        setOpaque(false);
        
        // Title label with bold font
        titleLabel = new JLabel(title);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
        
        // Help icon [❓]
        helpIcon = new JLabel(" [❓]");
        helpIcon.setFont(helpIcon.getFont().deriveFont(11f));
        helpIcon.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        helpIcon.setForeground(new Color(100, 100, 100));
        
        if (helpText != null && !helpText.isEmpty()) {
            helpIcon.setToolTipText(formatHelpText(helpText));
            helpIcon.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    showHelpDialog(title, SectionHeader.this.helpText);
                }
                
                @Override
                public void mouseEntered(MouseEvent e) {
                    helpIcon.setForeground(new Color(0, 100, 200));
                }
                
                @Override
                public void mouseExited(MouseEvent e) {
                    helpIcon.setForeground(new Color(100, 100, 100));
                }
            });
        } else {
            helpIcon.setVisible(false);
        }
        
        // Gear icon [⚙️]
        gearIcon = new JLabel(" [⚙]");
        gearIcon.setFont(gearIcon.getFont().deriveFont(11f));
        gearIcon.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        gearIcon.setForeground(new Color(100, 100, 100));
        
        // Gear popup menu
        gearMenu = new JPopupMenu();
        
        gearIcon.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (gearMenu.getComponentCount() > 0) {
                    gearMenu.show(gearIcon, 0, gearIcon.getHeight());
                }
            }
            
            @Override
            public void mouseEntered(MouseEvent e) {
                gearIcon.setForeground(new Color(0, 100, 200));
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                gearIcon.setForeground(new Color(100, 100, 100));
            }
        });
        
        // Layout components
        add(titleLabel);
        add(helpIcon);
        add(gearIcon);
        add(Box.createHorizontalGlue());
        
        // Add gear menu items if actions provided
        if (onRestoreDefaults != null) {
            addGearMenuItem("Restore Defaults", e -> onRestoreDefaults.run());
        }
        if (onSave != null) {
            addGearMenuItem("Save Settings", e -> onSave.run());
        }
        if (onReload != null) {
            addGearMenuItem("Reload from Disk", e -> onReload.run());
        }
        
        // Hide gear icon if no menu items
        if (gearMenu.getComponentCount() == 0) {
            gearIcon.setVisible(false);
        }
    }
    
    /**
     * Sets the help text displayed on hover and click.
     * 
     * @param text The help text
     */
    public void setHelpText(String text) {
        this.helpText = text;
        if (text != null && !text.isEmpty()) {
            helpIcon.setToolTipText(formatHelpText(text));
            helpIcon.setVisible(true);
        } else {
            helpIcon.setVisible(false);
        }
    }
    
    /**
     * Adds a menu item to the gear menu.
     * 
     * @param label The menu item label
     * @param action The action to perform when clicked
     */
    public void addGearMenuItem(String label, ActionListener action) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(action);
        gearMenu.add(item);
        gearIcon.setVisible(true);
    }
    
    /**
     * Adds a menu item with icon to the gear menu.
     * 
     * @param label The menu item label
     * @param icon The icon to display
     * @param action The action to perform when clicked
     */
    public void addGearMenuItem(String label, Icon icon, ActionListener action) {
        JMenuItem item = new JMenuItem(label, icon);
        item.addActionListener(action);
        gearMenu.add(item);
        gearIcon.setVisible(true);
    }
    
    /**
     * Adds a separator to the gear menu.
     */
    public void addGearMenuSeparator() {
        gearMenu.addSeparator();
    }
    
    /**
     * Shows or hides the gear icon.
     * 
     * @param visible Whether the gear icon should be visible
     */
    public void setGearIconVisible(boolean visible) {
        gearIcon.setVisible(visible);
    }
    
    /**
     * Shows or hides the help icon.
     * 
     * @param visible Whether the help icon should be visible
     */
    public void setHelpIconVisible(boolean visible) {
        helpIcon.setVisible(visible);
    }
    
    /**
     * Gets the title label component for additional customization.
     * 
     * @return The title JLabel
     */
    public JLabel getTitleLabel() {
        return titleLabel;
    }
    
    /**
     * Sets the title text.
     * 
     * @param title The new title
     */
    public void setTitle(String title) {
        titleLabel.setText(title);
    }
    
    /**
     * Formats help text for tooltip display (wraps long text in HTML).
     */
    private String formatHelpText(String text) {
        if (text == null) return null;
        
        // Wrap in HTML for better tooltip formatting
        String wrapped = "<html><body style='width: 300px; padding: 5px;'>" +
                text.replace("\n", "<br>") +
                "</body></html>";
        return wrapped;
    }
    
    /**
     * Shows a dialog with the full help text.
     */
    private void showHelpDialog(String title, String text) {
        if (text == null || text.isEmpty()) return;
        
        JTextArea textArea = new JTextArea(text);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setBackground(UIManager.getColor("Panel.background"));
        textArea.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(400, 200));
        scrollPane.setBorder(null);
        
        JOptionPane.showMessageDialog(
            SwingUtilities.getWindowAncestor(this),
            scrollPane,
            title + " - Help",
            JOptionPane.INFORMATION_MESSAGE
        );
    }
    
    /**
     * Creates a standard section header with restore defaults and save options.
     * 
     * @param title The section title
     * @param helpText The help text
     * @param onRestoreDefaults Action for restore defaults
     * @param onSave Action for save
     * @param onReload Action for reload
     * @return Configured SectionHeader
     */
    public static SectionHeader createStandard(String title, String helpText,
                                                Runnable onRestoreDefaults,
                                                Runnable onSave,
                                                Runnable onReload) {
        SectionHeader header = new SectionHeader(title, helpText);
        
        if (onRestoreDefaults != null) {
            header.addGearMenuItem("Restore Defaults", e -> onRestoreDefaults.run());
        }
        if (onSave != null) {
            header.addGearMenuItem("Save Settings", e -> onSave.run());
        }
        if (onReload != null) {
            header.addGearMenuItem("Reload from Disk", e -> onReload.run());
        }
        
        return header;
    }
    
    /**
     * Creates a minimal section header with only title (no icons).
     * 
     * @param title The section title
     * @return Configured SectionHeader
     */
    public static SectionHeader createMinimal(String title) {
        SectionHeader header = new SectionHeader(title);
        header.setHelpIconVisible(false);
        header.setGearIconVisible(false);
        return header;
    }
}
