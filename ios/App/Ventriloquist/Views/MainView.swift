import SwiftUI
import VQPhoneCore

/// SPEC §5.1 Main (Dictate).
struct MainView: View {
    @Environment(AppModel.self) private var model
    @State private var showHosts = false

    var body: some View {
        @Bindable var model = model
        NavigationStack {
            VStack(spacing: 0) {
                if let problem = model.identityProblem {
                    Banner(text: problem, systemImage: "exclamationmark.triangle.fill", tint: .orange)
                }
                if let problem = model.hostsProblem {
                    Banner(text: problem, systemImage: "exclamationmark.triangle.fill", tint: .orange)
                }
                if model.indicator != .secure {
                    Banner(text: "Not connected — will send when connected",
                           systemImage: "antenna.radiowaves.left.and.right", tint: Color.secondary)
                }
                if let radio = radioMessage {
                    Banner(text: radio, systemImage: "bolt.horizontal.circle", tint: .orange)
                }
                content
                RecordControls()
                    .padding(.vertical, 20)
            }
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Button { showHosts = true } label: { HostHeader() }
                        .accessibilityLabel("Choose desktop")
                }
            }
            .navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $showHosts) { HostPickerSheet() }
        }
    }

    @ViewBuilder private var content: some View {
        @Bindable var model = model
        if model.isRecording || model.currentId == nil {
            LiveTranscript()
        } else {
            VStack(alignment: .leading, spacing: 12) {
                TextEditor(text: $model.editText)
                    .font(.body)
                    .scrollContentBackground(.hidden)
                    .padding(8)
                    .background(.quaternary.opacity(0.5), in: .rect(cornerRadius: 12))
                Button {
                    model.sendCorrection()
                } label: {
                    Label("Send correction", systemImage: "arrow.up.circle.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!model.canSendCorrection)
            }
            .padding()
        }
    }

    private var radioMessage: String? {
        switch model.radioState {
        case .poweredOff: "Bluetooth is off"
        case .unauthorized: "Bluetooth access is off — enable it in Settings"
        case .unsupported: "Bluetooth LE is not available on this device"
        case .advertisingFailed: "Bluetooth is not advertising yet — retrying"
        case .unknown, .ready: nil
        }
    }
}

/// Active desktop name with the status dot (green / amber / grey).
struct HostHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(dotColor)
                .frame(width: 10, height: 10)
            Text(model.activeHostName ?? "No desktop")
                .font(.headline)
                .foregroundStyle(.primary)
            Image(systemName: "chevron.down")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
        }
    }

    private var dotColor: Color {
        switch model.indicator {
        case .secure: .green
        case .connecting: .orange
        case .none: .gray
        }
    }
}

/// Volatile text in secondary color after finalized text in primary color;
/// auto-scrolls to the end.
struct LiveTranscript: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let d = model.dictation
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading) {
                    if d.finalizedText.isEmpty && d.volatileText.isEmpty {
                        Text(model.isRecording ? "Listening…" : "Tap the button and start speaking.")
                            .foregroundStyle(.tertiary)
                    } else {
                        Text(styled(final: d.finalizedText, volatile: d.volatileText))
                            .font(.title3)
                            .textSelection(.enabled)
                    }
                    Color.clear.frame(height: 1).id("end")
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
            .onChange(of: d.finalizedText + d.volatileText) {
                withAnimation(.easeOut(duration: 0.15)) { proxy.scrollTo("end", anchor: .bottom) }
            }
        }
        .overlay {
            if case .preparingModel(let fraction) = d.phase {
                VStack(spacing: 8) {
                    ProgressView(value: fraction ?? 0)
                    Text("Downloading the speech model…").font(.footnote)
                }
                .padding()
                .background(.regularMaterial, in: .rect(cornerRadius: 12))
                .padding()
            }
        }
    }
}

/// Finalized text in the primary color, volatile text in the secondary color.
private func styled(final: String, volatile: String) -> AttributedString {
    var head = AttributedString(final)
    head.foregroundColor = .primary
    var tail = AttributedString(DictationEngine.separator(final, volatile) + volatile)
    tail.foregroundColor = .secondary
    return head + tail
}

/// The large circular record button; pulses red while recording.
struct RecordControls: View {
    @Environment(AppModel.self) private var model
    @State private var pulse = false

    var body: some View {
        Button {
            Task { await model.toggleRecording() }
        } label: {
            ZStack {
                Circle()
                    .fill(model.isRecording ? Color.red : Color.accentColor)
                    .frame(width: 88, height: 88)
                    .scaleEffect(model.isRecording && pulse ? 1.08 : 1.0)
                    .shadow(color: (model.isRecording ? Color.red : .clear).opacity(0.5),
                            radius: model.isRecording && pulse ? 16 : 4)
                Image(systemName: model.isRecording ? "stop.fill" : "mic.fill")
                    .font(.system(size: 34, weight: .semibold))
                    .foregroundStyle(.white)
            }
        }
        .buttonStyle(.plain)
        .disabled(isBusy)
        .accessibilityLabel(model.isRecording ? "Stop recording" : "Start recording")
        .onChange(of: model.isRecording, initial: true) { _, recording in
            if recording {
                withAnimation(.easeInOut(duration: 0.7).repeatForever(autoreverses: true)) { pulse = true }
            } else {
                withAnimation(.default) { pulse = false }
            }
        }
    }

    private var isBusy: Bool {
        switch model.dictation.phase {
        case .stopping: true
        case .preparingModel: !model.isRecording  // while starting, the button cancels
        default: false
        }
    }
}

struct Banner: View {
    let text: String
    let systemImage: String
    let tint: Color

    var body: some View {
        Label(text, systemImage: systemImage)
            .font(.footnote)
            .foregroundStyle(tint)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(.quaternary.opacity(0.4))
    }
}
