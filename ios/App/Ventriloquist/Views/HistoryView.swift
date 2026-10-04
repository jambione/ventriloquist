import SwiftData
import SwiftUI
import VQPhoneCore

/// SPEC §5.1 History: newest first, delivery status, copy, Re-send, swipe to
/// delete, Clear all with confirmation.
struct HistoryView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.modelContext) private var context
    @Query(sort: \HistoryEntry.createdAt, order: .reverse) private var entries: [HistoryEntry]
    @State private var confirmClear = false

    var body: some View {
        NavigationStack {
            List {
                ForEach(entries) { entry in
                    NavigationLink {
                        HistoryDetail(entry: entry)
                    } label: {
                        HistoryRow(entry: entry)
                    }
                    .contextMenu {
                        Button("Copy", systemImage: "doc.on.doc") { UIPasteboard.general.string = entry.text }
                        Button("Re-send", systemImage: "arrow.clockwise") { model.resend(entry) }
                    }
                    .swipeActions(edge: .leading) {
                        Button("Re-send", systemImage: "arrow.clockwise") { model.resend(entry) }
                            .tint(.blue)
                    }
                }
                .onDelete { offsets in
                    for i in offsets { model.delete(entries[i], context: context) }
                }
            }
            .overlay {
                if entries.isEmpty {
                    ContentUnavailableView("No dictations yet", systemImage: "text.bubble",
                                           description: Text("What you dictate appears here."))
                }
            }
            .navigationTitle("History")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Clear all", role: .destructive) { confirmClear = true }
                        .disabled(entries.isEmpty)
                }
            }
            .confirmationDialog("Delete all history?", isPresented: $confirmClear, titleVisibility: .visible) {
                Button("Clear all", role: .destructive) { model.clearHistory(entries) }
            } message: {
                Text("This removes every entry from this iPhone. Desktop logs are not affected.")
            }
        }
    }
}

struct HistoryRow: View {
    let entry: HistoryEntry

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(entry.text.isEmpty ? " " : entry.text).lineLimit(3)
                Text(entry.createdAt, format: .dateTime.month().day().hour().minute().second())
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            StatusIcon(status: entry.status)
        }
    }
}

struct StatusIcon: View {
    let status: DeliveryStatus

    var body: some View {
        switch status {
        case .acked:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green).accessibilityLabel("Delivered")
        case .pending:
            Image(systemName: "hourglass").foregroundStyle(.orange).accessibilityLabel("Pending")
        case .failed:
            Image(systemName: "xmark.circle.fill").foregroundStyle(.red).accessibilityLabel("Failed")
        }
    }
}

struct HistoryDetail: View {
    @Environment(AppModel.self) private var model
    let entry: HistoryEntry
    @State private var copied = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text(entry.text)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                HStack {
                    StatusIcon(status: entry.status)
                    Text(entry.createdAt, format: .dateTime)
                    if let host = entry.hostName { Text("· \(host)") }
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
            .padding()
        }
        .navigationTitle("Dictation")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .bottomBar) {
                Button(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc") {
                    UIPasteboard.general.string = entry.text
                    copied = true
                }
                Spacer()
                Button("Re-send", systemImage: "arrow.clockwise") { model.resend(entry) }
            }
        }
    }
}
