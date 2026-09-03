// Copyright 2026 the garak Bridge authors
// SPDX-License-Identifier: Apache-2.0

package burp.garak.ui;

import burp.garak.GarakContext;
import burp.garak.garakproc.PluginCatalog;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The probe picker.
 *
 * <p>garak ships 195 probes and the difference between them matters a great deal: some are
 * a handful of prompts, some are thousands; some need an attacker model this bridge cannot
 * provide. The catalogue's tier, tags and goal are surfaced so a choice can be made on
 * evidence, and probes that cannot work through the bridge are marked rather than hidden,
 * so their absence is explained rather than mysterious.
 */
public final class ProbePanel extends JPanel {

    private static final String ANY = "(any)";

    private final GarakContext context;

    private final JComboBox<String> presetChooser = new JComboBox<>();
    private final JComboBox<String> familyFilter = new JComboBox<>();
    private final JComboBox<String> tierFilter =
            new JComboBox<>(new String[]{ANY, "1", "2", "3", "9"});
    private final JComboBox<String> tagFilter = new JComboBox<>();
    private final JCheckBox readyOnly = new JCheckBox("Runnable through the bridge only", true);
    private final JCheckBox activeOnly = new JCheckBox("Active probes only", true);
    private final JTextField search = new JTextField(18);

    private final ProbeTableModel model = new ProbeTableModel();
    private final JTable table = new JTable(model);
    private final JLabel summary = Ui.hint(" ");

    private List<PluginCatalog.Preset> presets = List.of();

    public ProbePanel(GarakContext context) {
        super(new BorderLayout(6, 6));
        this.context = context;

        add(filters(), BorderLayout.NORTH);
        add(tableArea(), BorderLayout.CENTER);
        add(footer(), BorderLayout.SOUTH);

        model.selected.addAll(context.runConfig().probes);
    }

    // ------------------------------------------------------------------- layout

    private JPanel filters() {
        JPanel presetRow = Ui.row(
                Ui.bold("Preset:"), presetChooser,
                Ui.button("Apply preset", event -> applyPreset()),
                Ui.gap(12),
                Ui.button("Reload catalogue", event -> reload()));

        search.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent event) {
                refresh();
            }

            @Override
            public void removeUpdate(DocumentEvent event) {
                refresh();
            }

            @Override
            public void changedUpdate(DocumentEvent event) {
                refresh();
            }
        });
        familyFilter.addActionListener(event -> refresh());
        tierFilter.addActionListener(event -> refresh());
        tagFilter.addActionListener(event -> refresh());
        readyOnly.addActionListener(event -> refresh());
        activeOnly.addActionListener(event -> refresh());

        JPanel filterRow = Ui.row(
                Ui.label("Family:"), familyFilter,
                Ui.label("Tier:"), tierFilter,
                Ui.label("Tag:"), tagFilter,
                Ui.label("Search:"), search,
                readyOnly, activeOnly);

        JPanel panel = new JPanel();
        panel.setLayout(new javax.swing.BoxLayout(panel, javax.swing.BoxLayout.Y_AXIS));
        panel.add(presetRow);
        panel.add(filterRow);
        return panel;
    }

    private JScrollPane tableArea() {
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setRowHeight(table.getRowHeight() + 4);
        table.setFillsViewportHeight(true);

        setColumnWidth(0, 34, 34);
        setColumnWidth(1, 220, 260);
        setColumnWidth(2, 40, 46);
        setColumnWidth(3, 300, 420);
        setColumnWidth(4, 150, 190);

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));
        return scroll;
    }

    private void setColumnWidth(int index, int preferred, int max) {
        TableColumn column = table.getColumnModel().getColumn(index);
        column.setPreferredWidth(preferred);
        column.setMaxWidth(max);
    }

    private JPanel footer() {
        JPanel panel = Ui.row(
                Ui.button("Select all shown", event -> selectAllShown(true)),
                Ui.button("Deselect all shown", event -> selectAllShown(false)),
                Ui.button("Clear selection", event -> {
                    model.selected.clear();
                    commit();
                }));
        panel.add(Ui.gap(12));
        panel.add(summary);
        return panel;
    }

    // ------------------------------------------------------------------ catalogue

    /** Repopulates from whatever catalogue the context currently holds. */
    public void reload() {
        PluginCatalog catalogue = context.catalogue();

        familyFilter.removeAllItems();
        familyFilter.addItem(ANY);
        catalogue.families().forEach(familyFilter::addItem);

        tagFilter.removeAllItems();
        tagFilter.addItem(ANY);
        catalogue.tags().forEach(tagFilter::addItem);

        presets = PluginCatalog.presets();
        presetChooser.removeAllItems();
        presets.forEach(preset -> presetChooser.addItem(preset.name()));

        refresh();
    }

    private void refresh() {
        PluginCatalog catalogue = context.catalogue();
        String family = (String) familyFilter.getSelectedItem();
        String tier = (String) tierFilter.getSelectedItem();
        String tag = (String) tagFilter.getSelectedItem();
        String needle = search.getText().trim().toLowerCase(Locale.ROOT);

        List<PluginCatalog.Probe> shown = new ArrayList<>();
        for (PluginCatalog.Probe probe : catalogue.probes()) {
            if (activeOnly.isSelected() && !probe.active()) {
                continue;
            }
            if (readyOnly.isSelected() && !probe.isReadyToRun()) {
                continue;
            }
            if (family != null && !ANY.equals(family) && !probe.family().equals(family)) {
                continue;
            }
            if (tier != null && !ANY.equals(tier) && probe.tier() != Integer.parseInt(tier)) {
                continue;
            }
            if (tag != null && !ANY.equals(tag) && !probe.tags().contains(tag)) {
                continue;
            }
            if (!needle.isEmpty() && !matches(probe, needle)) {
                continue;
            }
            shown.add(probe);
        }

        model.setRows(shown);
        updateSummary();
    }

    private static boolean matches(PluginCatalog.Probe probe, String needle) {
        return probe.shortName().toLowerCase(Locale.ROOT).contains(needle)
                || probe.goal().toLowerCase(Locale.ROOT).contains(needle)
                || probe.description().toLowerCase(Locale.ROOT).contains(needle)
                || probe.tags().stream().anyMatch(tag -> tag.toLowerCase(Locale.ROOT).contains(needle));
    }

    private void applyPreset() {
        int index = presetChooser.getSelectedIndex();
        if (index < 0 || index >= presets.size()) {
            return;
        }
        PluginCatalog.Preset preset = presets.get(index);
        List<String> resolved = context.catalogue().resolve(preset);
        if (resolved.isEmpty()) {
            summary.setText("Preset \"" + preset.name() + "\" matched no probes in this catalogue.");
            return;
        }
        model.selected.clear();
        model.selected.addAll(resolved);
        commit();
        model.fireTableDataChanged();
    }

    private void selectAllShown(boolean select) {
        for (PluginCatalog.Probe probe : model.rows) {
            if (select) {
                model.selected.add(probe.name());
            } else {
                model.selected.remove(probe.name());
            }
        }
        commit();
        model.fireTableDataChanged();
    }

    /** Writes the selection into the run config and persists it. */
    private void commit() {
        context.runConfig().probes = new ArrayList<>(model.selected);
        context.saveRunConfig();
        updateSummary();
    }

    private void updateSummary() {
        int selected = model.selected.size();
        int shown = model.rows.size();
        int total = context.catalogue().probes().size();
        String source = context.catalogue().isEmpty()
                ? "no catalogue loaded — set the garak path in Settings"
                : "from " + context.catalogue().source();
        summary.setText(selected + " selected · " + shown + " shown of " + total + " · " + source);
    }

    // ---------------------------------------------------------------- table model

    private final class ProbeTableModel extends AbstractTableModel {

        private final String[] columns = {"", "Probe", "Tier", "Goal", "Detector", "Notes"};
        private final List<PluginCatalog.Probe> rows = new ArrayList<>();
        private final Set<String> selected = new LinkedHashSet<>();

        void setRows(List<PluginCatalog.Probe> probes) {
            rows.clear();
            rows.addAll(probes);
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            return column == 0 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 0;
        }

        @Override
        public Object getValueAt(int row, int column) {
            PluginCatalog.Probe probe = rows.get(row);
            return switch (column) {
                case 0 -> selected.contains(probe.name());
                case 1 -> probe.shortName();
                case 2 -> probe.tier() > 0 ? String.valueOf(probe.tier()) : "";
                case 3 -> probe.goal().isBlank()
                        ? Ui.ellipsis(probe.description(), 110)
                        : Ui.ellipsis(probe.goal(), 110);
                case 4 -> probe.primaryDetector();
                default -> caveatOrTags(probe);
            };
        }

        private String caveatOrTags(PluginCatalog.Probe probe) {
            String caveat = probe.caveat();
            if (!caveat.isEmpty()) {
                return "⚠ " + caveat;
            }
            List<String> owasp = probe.owaspTags();
            return owasp.isEmpty() ? "" : String.join(", ", owasp);
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (column != 0) {
                return;
            }
            PluginCatalog.Probe probe = rows.get(row);
            if (Boolean.TRUE.equals(value)) {
                selected.add(probe.name());
            } else {
                selected.remove(probe.name());
            }
            commit();
        }
    }
}
