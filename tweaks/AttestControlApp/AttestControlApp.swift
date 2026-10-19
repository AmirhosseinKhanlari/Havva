// Minimal control app that DEFINITELY uses App Attest, to validate the detector.
//
// Purpose: inject AttestObserver.dylib into a build of this app and confirm the
// syslog shows OBSERVER_LOADED -> CLASS_PRESENT -> HOOK_VERIFIED -> CALL. If the
// markers fire here (a known positive), the detector is trustworthy and a
// *negative* on a real app is meaningful. See tweaks/AttestObserver.
//
// Build: create a SwiftUI iOS app target, drop this in, run on the XR. It calls
// DCAppAttestService on launch (no server needed to trigger the CALL markers).

import SwiftUI
import DeviceCheck

@main
struct AttestControlApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

struct ContentView: View {
    @State private var status = "starting…"
    var body: some View {
        VStack(spacing: 16) {
            Text("App Attest Control").font(.headline)
            Text(status).font(.footnote).multilineTextAlignment(.center).padding()
        }
        .onAppear(perform: exercise)
    }

    func exercise() {
        let service = DCAppAttestService.shared
        guard service.isSupported else { status = "App Attest not supported here"; return }
        // generateKey -> attestKey -> generateAssertion: fires all three CALL markers.
        service.generateKey { keyId, err in
            if let err = err { setStatus("generateKey error: \(err.localizedDescription)"); return }
            guard let keyId = keyId else { setStatus("no keyId"); return }
            let challenge = Data("control-challenge".utf8)
            let hash = Data(SHA256Wrapper.hash(challenge))
            service.attestKey(keyId, clientDataHash: hash) { _, aerr in
                if let aerr = aerr { setStatus("attestKey error: \(aerr.localizedDescription)") }
                service.generateAssertion(keyId, clientDataHash: hash) { _, gerr in
                    setStatus(gerr == nil ? "assertion generated (markers should have fired)"
                                          : "assertion error: \(gerr!.localizedDescription)")
                }
            }
        }
    }

    func setStatus(_ s: String) { DispatchQueue.main.async { status = s } }
}

import CryptoKit
enum SHA256Wrapper {
    static func hash(_ data: Data) -> [UInt8] { Array(SHA256.hash(data: data)) }
}
