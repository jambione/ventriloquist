import SwiftUI
import VQPhoneCore

/// SPEC §5.1 Host picker: Paired (online/offline) and Nearby, not paired.
struct HostPickerSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section("Paired") {
                    if paired.isEmpty {
                        Text("No paired desktops yet.").foregroundStyle(.secondary)
                    }
                    ForEach(paired) { host in
                        Button {
                            model.select(host)
                            dismiss()
                        } label: {
                            PairedRow(host: host)
                        }
                        .swipeActions {
                            Button("Forget", role: .destructive) { model.forget(host) }
                        }
                    }
                }
                Section {
                    if nearby.isEmpty {
                        HStack(spacing: 8) {
                            ProgressView()
                            Text("Looking for desktops running Ventriloquist…")
                                .foregroundStyle(.secondary)
                        }
                    }
                    ForEach(nearby) { host in
                        Button {
                            model.select(host)
                        } label: {
                            HStack {
                                Image(systemName: "desktopcomputer")
                                VStack(alignment: .leading) {
                                    Text(host.name).foregroundStyle(.primary)
                                    if host.keyChanged {
                                        Text("Its key changed — pair again").font(.caption).foregroundStyle(.orange)
                                    }
                                }
                                Spacer()
                                Text("Pair").foregroundStyle(.tint)
                            }
                        }
                    }
                } header: {
                    Text("Nearby, not paired")
                } footer: {
                    Text("Desktops appear here when the Ventriloquist desktop app is running nearby.")
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
            .navigationTitle("Desktops")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
            .sheet(isPresented: Binding(
                get: { model.pairing != nil },
                set: { if !$0 { model.dismissPairing() } }
            )) {
                PairingCodeSheet()
                    .presentationDetents([.medium, .large])
                    .interactiveDismissDisabled(isVerifying)
            }
        }
    }

    private var paired: [HostInfo] { model.hosts.filter(\.isPaired) }
    private var nearby: [HostInfo] { model.hosts.filter { !$0.isPaired && $0.isOnline } }

    private var isVerifying: Bool {
        model.pairing?.phase == .verifying
    }
}

private struct PairedRow: View {
    let host: HostInfo

    var body: some View {
        HStack {
            Image(systemName: "desktopcomputer")
            VStack(alignment: .leading, spacing: 2) {
                Text(host.name).foregroundStyle(.primary)
                if host.notRecognized {
                    Text("Not recognised — swipe to Forget, then pair again")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            Text(badge)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(badgeColor.opacity(0.15), in: .capsule)
                .foregroundStyle(badgeColor)
            if host.isActive {
                Image(systemName: "checkmark").foregroundStyle(.tint)
            }
        }
    }

    private var badge: String {
        switch host.state {
        case .secure: "Online"
        case .offline: "Offline"
        case .pairing, .unpaired: "Connecting"
        }
    }

    private var badgeColor: Color {
        switch host.state {
        case .secure: .green
        case .offline: .gray
        case .pairing, .unpaired: .orange
        }
    }
}

/// 6-digit code entry: numeric keypad, auto-submits on the 6th digit, clear
/// error states (SPEC §5.1).
struct PairingCodeSheet: View {
    @Environment(AppModel.self) private var model
    @State private var code = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 20) {
            if let p = model.pairing {
                Text("Pair with \(p.hostName)")
                    .font(.title2.bold())
                    .multilineTextAlignment(.center)
                switch p.phase {
                case .requesting:
                    ProgressView("Asking \(p.hostName) for a code…")
                    note(p)
                case .enterCode(let error):
                    Text("Enter the 6-digit code shown on \(p.hostName).")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                    codeField
                    if let error {
                        Label(error, systemImage: "xmark.octagon.fill")
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                    }
                    note(p)
                    Button("Get a new code") {
                        code = ""
                        model.requestNewCode()
                    }
                    .font(.footnote)
                case .verifying:
                    codeField.disabled(true)
                    ProgressView("Checking…")
                case .succeeded:
                    Label("Paired", systemImage: "checkmark.circle.fill")
                        .font(.title3)
                        .foregroundStyle(.green)
                    Button("Done") { model.dismissPairing() }
                        .buttonStyle(.borderedProminent)
                case .failed(let message):
                    Label(message, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                    HStack {
                        Button("Close") { model.dismissPairing() }
                        if model.hosts.contains(where: { $0.id == p.hostId && $0.isOnline && !$0.isPaired }) {
                            Button(p.retryIn > 0 ? "Try again in \(p.retryIn) s" : "Try again") {
                                code = ""
                                model.retryPairing()
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(p.retryIn > 0)
                        }
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(24)
        .onChange(of: model.pairing?.phase) { _, phase in
            if case .enterCode(let error) = phase {
                if error != nil || code.count == 6 { code = "" }
                focused = true
            }
        }
    }

    @ViewBuilder private func note(_ p: PairingStatus) -> some View {
        if let note = p.note {
            Text(note).font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
    }

    private var codeField: some View {
        TextField("000000", text: $code)
            .keyboardType(.numberPad)
            .textContentType(.oneTimeCode)
            .font(.system(size: 36, weight: .semibold, design: .monospaced))
            .multilineTextAlignment(.center)
            .focused($focused)
            .frame(maxWidth: 240)
            .padding(.vertical, 8)
            .background(.quaternary.opacity(0.5), in: .rect(cornerRadius: 12))
            .onAppear { focused = true }
            .onChange(of: code) { _, new in
                let digits = String(new.unicodeScalars.filter { ("0"..."9").contains($0) }.prefix(6).map(Character.init))
                if digits != new {
                    code = digits
                    return
                }
                if digits.count == 6 { model.submitCode(digits) }
            }
    }
}
