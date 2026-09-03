// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.ui;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionListener;

/** Small Swing helpers, so the panels read as layout rather than boilerplate. */
public final class Ui {

    private Ui() {
    }

    public static JPanel row(Component... components) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        for (Component component : components) {
            panel.add(component);
        }
        return panel;
    }

    public static JPanel column(Component... components) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        for (Component component : components) {
            if (component instanceof JComponent child) {
                child.setAlignmentX(Component.LEFT_ALIGNMENT);
            }
            panel.add(component);
        }
        return panel;
    }

    public static JPanel titled(String title, Component content) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(content, BorderLayout.CENTER);
        return panel;
    }

    public static JButton button(String text, ActionListener action) {
        JButton button = new JButton(text);
        button.addActionListener(action);
        return button;
    }

    public static JLabel label(String text) {
        return new JLabel(text);
    }

    /** Secondary text: explanations, hints, counts. */
    public static JLabel hint(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.PLAIN,
                label.getFont().getSize2D() - 1f));
        label.setForeground(muted(label.getForeground()));
        return label;
    }

    public static JLabel bold(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        return label;
    }

    /**
     * Dims a colour towards the background without assuming a light or dark theme --
     * Burp ships both, and a hard-coded grey is unreadable in one of them.
     */
    public static Color muted(Color foreground) {
        return new Color(foreground.getRed(), foreground.getGreen(), foreground.getBlue(), 170);
    }

    public static JTextArea monospace(int rows, int columns) {
        JTextArea area = new JTextArea(rows, columns);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, area.getFont().getSize()));
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }

    public static JScrollPane scroll(Component content) {
        JScrollPane pane = new JScrollPane(content);
        pane.setBorder(BorderFactory.createEmptyBorder());
        return pane;
    }

    public static Component gap(int width) {
        return Box.createHorizontalStrut(width);
    }

    public static Component vgap(int height) {
        return Box.createVerticalStrut(height);
    }

    /** Fixes a component's height so a BoxLayout cannot stretch it. */
    public static <T extends JComponent> T fixHeight(T component, int height) {
        component.setMaximumSize(new Dimension(Integer.MAX_VALUE, height));
        component.setPreferredSize(new Dimension(component.getPreferredSize().width, height));
        return component;
    }

    /** Runs on the Swing thread, whether or not the caller is already on it. */
    public static void onEdt(Runnable action) {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeLater(action);
        }
    }

    /** Shortens text for a table cell or label. */
    public static String ellipsis(String text, int limit) {
        if (text == null) {
            return "";
        }
        String flat = text.replace('\n', ' ').replace('\r', ' ').trim();
        return flat.length() <= limit ? flat : flat.substring(0, limit - 1) + "…";
    }
}
