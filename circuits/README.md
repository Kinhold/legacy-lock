# Legacy Lock pure circuit sketch (documentation)

This Noir file records the extracted pure rules for future Aztec/Noir proving.
The shipping product today is the TypeScript package in `../src`.

Do not treat this as a deployed Aztec contract.

```noir
fn assert_time_unlocked(current_time: u64, unlock_at: u64) {
    assert(current_time >= unlock_at);
}

fn assert_heir_secret(secret: Field, commitment: Field) {
    // Archive used Pedersen; product TS uses SHA-256 domain-separated commitments.
    // Replace with Poseidon/Pedersen when wiring a real Noir prove path.
    assert(std::hash::pedersen_hash([secret]) == commitment);
}
```
