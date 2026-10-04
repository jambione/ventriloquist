# Local patch to btleplug 0.13.3

Upstream: https://crates.io/crates/btleplug/0.13.3 (MIT/Apache-2.0, see LICENSE.md).

Change: `src/winrtble/ble/device.rs` `discover_services` uses `BluetoothCacheMode::Uncached`
instead of `Cached`.

Why: the Ventriloquist iPhone app removes its GATT service in the background and re-adds it in
the foreground, renumbering attribute handles. iOS sends Service Changed only to bonded centrals,
and Ventriloquist does not use OS bonding, so Windows kept a stale handle table and subscribing to
TX failed with HRESULT 0x80650003 ("The attribute cannot be written").

Remove this vendored copy once upstream offers uncached discovery (or an option for it).
