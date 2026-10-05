@preconcurrency import AVFoundation
import SwiftUI

/// Camera QR scanner (SPEC_V3 §7): permission flow, then a live preview that
/// reports the first QR string. A valid `vq://pair` code pairs and dismisses.
struct QRScannerSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var access = AVCaptureDevice.authorizationStatus(for: .video)
    @State private var error: String?
    @State private var handled = false

    var body: some View {
        NavigationStack {
            Group {
                switch access {
                case .authorized: scanner
                case .notDetermined: ProgressView().task { await ask() }
                default: denied
                }
            }
            .navigationTitle("Scan QR code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }

    private var scanner: some View {
        ZStack(alignment: .bottom) {
            QRScannerRepresentable { string in
                guard !handled else { return }
                if let message = model.pair(scanned: string) {
                    error = message
                } else {
                    handled = true
                    dismiss()
                }
            }
            .ignoresSafeArea(edges: .bottom)
            VStack(spacing: 8) {
                if let error {
                    Label(error, systemImage: "xmark.octagon.fill").foregroundStyle(.red)
                } else {
                    Text("Point the camera at the QR code shown by Ventriloquist on your computer.")
                }
            }
            .multilineTextAlignment(.center)
            .padding()
            .frame(maxWidth: .infinity)
            .background(.regularMaterial)
        }
    }

    private var denied: some View {
        VStack(spacing: 16) {
            Image(systemName: "camera.fill").font(.system(size: 44)).foregroundStyle(.tint)
            Text("Camera access is off").font(.title2.bold())
            Text("Ventriloquist needs the camera to scan the QR code shown on your computer. Nothing is recorded or stored.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            Button("Open Settings") { model.openSettings() }.buttonStyle(.borderedProminent)
        }
        .padding(24)
    }

    private func ask() async {
        _ = await AVCaptureDevice.requestAccess(for: .video)
        access = AVCaptureDevice.authorizationStatus(for: .video)
    }
}

private struct QRScannerRepresentable: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> QRScannerController {
        let c = QRScannerController()
        c.onCode = onCode
        return c
    }

    func updateUIViewController(_ controller: QRScannerController, context: Context) {
        controller.onCode = onCode
    }
}

@MainActor
private final class QRScannerController: UIViewController, @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
    var onCode: (String) -> Void = { _ in }
    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?
    private var lastString: String?

    override func viewDidLoad() {
        super.viewDidLoad()
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(layer)
        preview = layer
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        let s = session
        DispatchQueue.global(qos: .userInitiated).async { if !s.isRunning { s.startRunning() } }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        let s = session
        DispatchQueue.global(qos: .userInitiated).async { if s.isRunning { s.stopRunning() } }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard let code = objects.compactMap({ ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }).first,
              code != lastString else { return }
        lastString = code
        onCode(code)
    }
}
