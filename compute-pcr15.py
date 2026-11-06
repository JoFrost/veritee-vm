import hashlib
import json

def simulate_tpm_extend(current_pcr: bytes, new_data: bytes) -> bytes:
    """Simulates a TPM2 PCR extend operation: SHA256(PCR || Data)"""
    assert len(current_pcr) == 32, "PCR must be 32 bytes"
    assert len(new_data) == 32, "Extended data must be 32 bytes"
    
    hasher = hashlib.sha256()
    hasher.update(current_pcr)
    hasher.update(new_data)
    return hasher.digest()

def calculate_expected_pcr15(disk_root_hash_hex: str, caddy_ca_string: str) -> str:
    # 0. Initial state of PCR 15 on boot (32 bytes of zeros)
    pcr = b'\x00' * 32
    
    # 3. Third Extension: Hash of the Ephemeral Caddy Root CA
    caddy_ca_hash = hashlib.sha256(caddy_ca_string.encode('utf-8')).digest()
    pcr = simulate_tpm_extend(pcr, caddy_ca_hash)
    
    return pcr.hex()

def verify_from_json(json_filepath: str):
    """Utility to pull the values directly from your JSON payload"""
    with open(json_filepath, 'r') as f:
        payload = json.load(f)
        
    disk_hash = payload['application_disk_roothash']
    caddy_ca = payload['webserver_rootca']
    
    print(f"[*] Extracting Root Hash from JSON: {disk_hash[:16]}...")
    print(f"[*] Extracting Caddy CA from JSON:  {caddy_ca[:30]}...")
    
    expected_pcr15 = calculate_expected_pcr15(disk_hash, caddy_ca)
    
    print("\n" + "="*50)
    print(f"EXPECTED PCR 15: {expected_pcr15}")
    print("="*50)

# --- Run the test ---
if __name__ == "__main__":
    # If you saved the curl output to attestation.json, just run this:
    verify_from_json("attestation.json")
    
    pass
