import SwiftData
import SwiftUI

@main
struct VentriloquistApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
        }
        .modelContainer(for: HistoryEntry.self)
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.modelContext) private var context
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        @Bindable var model = model
        TabView {
            Tab("Dictate", systemImage: "mic.fill") { MainView() }
            Tab("History", systemImage: "clock") { HistoryView() }
            Tab("Settings", systemImage: "gearshape") { SettingsView() }
        }
        .task { model.start(context: context) }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .background: model.enterBackground()
            case .active: model.enterForeground()
            default: break
            }
        }
        .alert("Ventriloquist", isPresented: Binding(
            get: { model.alertMessage != nil },
            set: { if !$0 { model.alertMessage = nil } }
        )) {
            Button("OK", role: .cancel) { model.alertMessage = nil }
        } message: {
            Text(model.alertMessage ?? "")
        }
        .sheet(item: Binding(
            get: { model.permissionProblem.map(PermissionSheetItem.init) },
            set: { if $0 == nil { model.permissionProblem = nil } }
        )) { item in
            PermissionView(problem: item.problem)
                .presentationDetents([.medium])
        }
    }
}

private struct PermissionSheetItem: Identifiable {
    let problem: AppModel.PermissionProblem
    var id: String { problem.title }
}

/// Explains a denied permission and links to Settings (SPEC §5.2).
struct PermissionView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let problem: AppModel.PermissionProblem

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: icon)
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text(problem.title).font(.title2.bold())
            Text(problem.explanation)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button("Open Settings") { model.openSettings() }
                .buttonStyle(.borderedProminent)
            Button("Not now") { dismiss() }
        }
        .padding(24)
    }

    private var icon: String {
        switch problem {
        case .microphone: "mic.slash"
        case .speech: "waveform.slash"
        case .bluetooth: "antenna.radiowaves.left.and.right.slash"
        }
    }
}
