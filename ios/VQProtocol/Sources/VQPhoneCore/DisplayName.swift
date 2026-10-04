import Foundation

/// Bounds and cleans names that come from outside (a desktop's `hello.name`)
/// or go outside (our own device name). The same rule as the desktop's
/// `normalize_name` (desktop/core/src/config.rs, K13): remove control and bidi
/// characters, trim, cap at 64 Unicode scalars.
public enum PhoneNames {
    /// Longest name kept, in Unicode scalars.
    public static let maxScalars = 64

    /// Control characters (C0, DEL, C1), bidi controls, line and paragraph
    /// separators.
    static func isUnsafe(_ s: Unicode.Scalar) -> Bool {
        if s.properties.generalCategory == .control { return true }
        switch s.value {
        case 0x061C, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069, 0x2028, 0x2029: return true
        default: return false
        }
    }

    /// `name` without unsafe characters, trimmed and capped; `fallback` if
    /// nothing is left.
    public static func clean(_ name: String, fallback: String) -> String {
        func trimmed(_ scalars: [Unicode.Scalar]) -> String {
            String(String.UnicodeScalarView(scalars)).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let kept = name.unicodeScalars.filter { !isUnsafe($0) }
        let first = trimmed(Array(kept))
        let capped = trimmed(Array(first.unicodeScalars.prefix(maxScalars)))
        return capped.isEmpty ? fallback : capped
    }
}
