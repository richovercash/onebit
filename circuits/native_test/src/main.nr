// Dependency-free circuit to validate the native proving pipeline on-device.
// Proves knowledge of a,b (private) with a*b == result (public).
fn main(a: Field, b: Field, result: pub Field) {
    assert(a * b == result);
}
