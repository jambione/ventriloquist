import SwiftUI
import VQPhoneCore

/// SPEC §5.1 Settings: custom vocabulary, device name, partial streaming.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var newTerm = ""

    var body: some View {
        @Bindable var model = model
        NavigationStack {
            Form {
                Section {
                    ForEach(Array(model.vocabulary.enumerated()), id: \.offset) { _, term in
                        Text(term)
                    }
                    .onDelete { model.vocabulary.remove(atOffsets: $0) }
                    .onMove { model.vocabulary.move(fromOffsets: $0, toOffset: $1) }
                    HStack {
                        TextField("Add a term, e.g. kubectl", text: $newTerm)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .onSubmit(addTerm)
                        Button("Add", action: addTerm)
                            .disabled(trimmed.isEmpty || model.vocabulary.count >= DictationEngine.maxContextualStrings)
                    }
                } header: {
                    Text("Custom vocabulary")
                } footer: {
                    Text("Words the recognizer should expect (up to \(DictationEngine.maxContextualStrings)). Short terms work best.")
                }

                Section {
                    TextField("Device name", text: $model.deviceName)
                } header: {
                    Text("Device name")
                } footer: {
                    Text("Shown to your desktops when they connect (up to \(PhoneNames.maxScalars) characters).")
                }

                Section {
                    Toggle("Stream live text", isOn: $model.partialStreaming)
                } footer: {
                    Text("When off, text is sent only when you stop recording or send a correction.")
                }
            }
            .navigationTitle("Settings")
            .toolbar { EditButton() }
        }
    }

    private var trimmed: String { newTerm.trimmingCharacters(in: .whitespacesAndNewlines) }

    private func addTerm() {
        let term = trimmed
        guard !term.isEmpty, !model.vocabulary.contains(term),
              model.vocabulary.count < DictationEngine.maxContextualStrings else { return }
        model.vocabulary.append(term)
        newTerm = ""
    }
}
