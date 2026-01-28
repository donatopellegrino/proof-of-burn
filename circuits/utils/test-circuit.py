import json
import subprocess
import os

def generate_witness(input_dict, wasm_path, witness_path):
    """
    Generate a witness for the circuit using snarkjs CLI.
    input_dict: dictionary of circuit inputs
    wasm_path: path to compiled .wasm file
    witness_path: output path for witness.wtns
    """
    # 1️⃣ Write input JSON
    input_json_path = "input.json"
    with open(input_json_path, "w") as f:
        json.dump(input_dict, f)

    # 2️⃣ Call snarkjs to generate witness
    # `snarkjs wtns calculate <wasm> <input.json> <witness.wtns>`
    cmd = ["snarkjs", "wtns", "calculate", wasm_path, input_json_path, witness_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Witness generation failed:")
        print(result.stdout)
        print(result.stderr)
        return False
    return True

def read_witness(witness_path):
    """
    Optional: read the witness file (binary .wtns)
    Can be parsed using snarkjs or kept as opaque
    """
    with open(witness_path, "rb") as f:
        data = f.read()
    return data

def test_burn_address_encrypt_fixed():
    # Hard-coded demo input
    input_data = {
        "burnKey": "12345",
        "revealAmount": "100",
        "burnExtraCommitment": "42"
    }

    wasm_path = "./BurnAddressEncryptFixed_js/BurnAddressEncryptFixed.wasm"
    witness_path = "witness.wtns"

    print("Generating witness...")
    success = generate_witness(input_data, wasm_path, witness_path)
    assert success, "Witness generation failed! Circuit constraints did not pass."

    print("✅ Witness generated successfully. Circuit constraints passed.")

    # Optional: inspect witness
    witness_bytes = read_witness(witness_path)
    print(f"Witness size: {len(witness_bytes)} bytes")

if __name__ == "__main__":
    test_burn_address_encrypt_fixed()
