import Foundation
import Testing

/// Every vector file, and every section in it, is checked by a test.
@Suite("vector coverage")
struct CoverageTests {
    @Test func everyFileAndSectionIsCovered() throws {
        let names = try FileManager.default.contentsOfDirectory(atPath: vectorsDir.path)
            .filter { $0.hasSuffix(".json") }
            .sorted()
        #expect(names == coveredSections.keys.sorted(), "vector files changed: \(names)")
        for name in names {
            let v = try loadVectors(name)
            #expect(v["description"].strOrNil != nil, "\(name): missing description")
            let sections = Set(v.keys).subtracting(["description", "vectors_version"])
            #expect(sections == coveredSections[name], "\(name): sections \(sections.sorted())")
        }
    }
}
