import Foundation
import SwiftData
import VQPhoneCore

/// One past utterance (SPEC §5.1 History). Stored with SwiftData.
@Model
final class HistoryEntry {
    /// The utterance id (`utt.id`).
    @Attribute(.unique) var utteranceId: UUID
    var text: String
    var createdAt: Date
    var statusRaw: String
    var hostName: String?

    init(utteranceId: UUID, text: String, createdAt: Date = .now, status: DeliveryStatus, hostName: String?) {
        self.utteranceId = utteranceId
        self.text = text
        self.createdAt = createdAt
        statusRaw = status.rawValue
        self.hostName = hostName
    }

    var status: DeliveryStatus {
        get { DeliveryStatus(rawValue: statusRaw) ?? .failed }
        set { statusRaw = newValue.rawValue }
    }
}

/// History bookkeeping: insert, status updates and the 1,000-entry cap.
@MainActor
struct HistoryStore {
    static let cap = 1_000
    let context: ModelContext
    /// Called with the utterance id of every entry removed (prune, clear), so
    /// the engine can release its per-id state (V4).
    var onRemove: ((UUID) -> Void)?

    func add(id: UUID, text: String, status: DeliveryStatus, hostName: String?) {
        context.insert(HistoryEntry(utteranceId: id, text: text, status: status, hostName: hostName))
        prune()
        save()
    }

    func entry(_ id: UUID) -> HistoryEntry? {
        var d = FetchDescriptor<HistoryEntry>(predicate: #Predicate { $0.utteranceId == id })
        d.fetchLimit = 1
        return try? context.fetch(d).first
    }

    func update(_ id: UUID, text: String? = nil, status: DeliveryStatus? = nil) {
        guard let e = entry(id) else { return }
        if let text { e.text = text }
        if let status { e.status = status }
        save()
    }

    /// Oldest entries beyond the cap are deleted first.
    func prune() {
        let count = (try? context.fetchCount(FetchDescriptor<HistoryEntry>())) ?? 0
        guard count > Self.cap else { return }
        var d = FetchDescriptor<HistoryEntry>(sortBy: [SortDescriptor(\.createdAt, order: .forward)])
        d.fetchLimit = count - Self.cap
        for e in (try? context.fetch(d)) ?? [] {
            onRemove?(e.utteranceId)
            context.delete(e)
        }
    }

    /// Deliveries do not survive a relaunch: anything still pending from a
    /// previous run is shown as failed, so the user can Re-send it.
    func failStalePending() {
        let pending = DeliveryStatus.pending.rawValue
        let d = FetchDescriptor<HistoryEntry>(predicate: #Predicate { $0.statusRaw == pending })
        for e in (try? context.fetch(d)) ?? [] { e.status = .failed }
        save()
    }

    func deleteAll() {
        // Batch delete does not refresh `@Query` (M21): delete each, then save.
        for e in (try? context.fetch(FetchDescriptor<HistoryEntry>())) ?? [] {
            onRemove?(e.utteranceId)
            context.delete(e)
        }
        save()
    }

    func save() {
        try? context.save()
    }
}
