#!/home/razvan/projejct/venv/bin/python3.11
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
from qiskit.visualization import plot_histogram
import random
import os
import numpy as np
import hashlib
from typing import List, Tuple, Dict

KEY_LENGTH = 128

def alice_bits(length: int = KEY_LENGTH) -> List[int]:
    alice_bits_list = []
    for i in range(length):
        a = random.randint(0, 1)
        alice_bits_list.append(a)
    return alice_bits_list

def gen_mask(length: int = KEY_LENGTH) -> List[int]:
    gen_mask_list = []
    for i in range(length):
        b = random.randint(0, 1)
        gen_mask_list.append(b)
    return gen_mask_list

def alice_qubits(bases: List[int], bits: List[int]) -> List[QuantumCircuit]:   
    quantum_circuits = []
    for i in range(len(bits)):
        qc = QuantumCircuit(1, 1, name=f'alice_qubit_{i}')
        if bits[i] == 1:
            qc.x(0)
        if bases[i] == 1:
            qc.h(0)
        quantum_circuits.append(qc)
    
    return quantum_circuits

def alice_sift_key(bits: List[int], alice_bases: List[int], bob_bases: List[int]) -> Tuple[List[int], List[int]]:
    sifted_key = []
    matching_indices = []
    
    for i, (alice_basis, bob_basis) in enumerate(zip(alice_bases, bob_bases)):
        if alice_basis == bob_basis:
            sifted_key.append(bits[i])
            matching_indices.append(i)
    
    print(f"Alice: Sifted key -we kept {len(sifted_key)}/{len(bits)} bits")
    return sifted_key, matching_indices

def bob_measure_qubits(quantum_states: List[QuantumCircuit], bob_bases: List[int]) -> List[int]:
    measurement_results = []
    backend = Aer.get_backend('qasm_simulator')
    
    for i, (qc, basis) in enumerate(zip(quantum_states, bob_bases)):
        measurement_circuit = qc.copy(name=f'bob_measurement_{i}')
        if basis == 1:
            measurement_circuit.h(0)
        measurement_circuit.measure(0, 0)

        tqc = transpile(measurement_circuit, backend)
        job = backend.run(tqc, shots=1)
        result = job.result()
        counts = result.get_counts()
        measured_bit = int(list(counts.keys())[0])
        measurement_results.append(measured_bit)
    
    print(f"Bob: Completed measurements of {len(quantum_states)} qubits")
    return measurement_results

def bob_sift_key(measurements: List[int], alice_bases: List[int], bob_bases: List[int]) -> Tuple[List[int], List[int]]:
    sifted_key = []
    matching_indices = []
    
    for i, (alice_basis, bob_basis) in enumerate(zip(alice_bases, bob_bases)):
        if alice_basis == bob_basis:
            sifted_key.append(measurements[i])
            matching_indices.append(i)
    
    print(f"Bob: Sifted key - we kept {len(sifted_key)}/{len(measurements)} bits")
    return sifted_key, matching_indices

def calculate_error_rate(alice_key: List[int], bob_key: List[int], sample_size: int = 10) -> float:
    if len(alice_key) < sample_size:
        sample_size = len(alice_key)
    
    if sample_size == 0:
        return 0.0
    
    test_indices = random.sample(range(len(alice_key)), sample_size)
    errors = sum(1 for idx in test_indices if alice_key[idx] != bob_key[idx])
    
    return errors / sample_size

def verify_keys(alice_key: List[int], bob_key: List[int]) -> bool:
    if len(alice_key) != len(bob_key):
        return False
    return alice_key == bob_key

def run_bb84_protocol(length: int = KEY_LENGTH) -> Tuple[Dict, List[int], List[int]]:
    protocol_dict = {}
    
    alice_bases = gen_mask(length)
    alice_bits_list = alice_bits(length)
    alice_qubits_list = alice_qubits(alice_bases, alice_bits_list)
    
    bob_bases = gen_mask(length)
    bob_measurements = bob_measure_qubits(alice_qubits_list, bob_bases)
    
    alice_sifted_key, alice_matching_indices = alice_sift_key(alice_bits_list, alice_bases, bob_bases)
    bob_sifted_key, bob_matching_indices = bob_sift_key(bob_measurements, alice_bases, bob_bases)
    
    keys_match = verify_keys(alice_sifted_key, bob_sifted_key)
    error_rate = 0.0
    
    if keys_match and len(alice_sifted_key) >= 10:
        error_rate = calculate_error_rate(alice_sifted_key, bob_sifted_key, min(10, len(alice_sifted_key)))
    
    protocol_dict = {
        'original_length': length,
        'alice_bases': alice_bases,
        'bob_bases': bob_bases,
        'alice_bits': alice_bits_list,
        'bob_measurements': bob_measurements,
        'matching_indices': alice_matching_indices,
        'final_key_length': len(alice_sifted_key),
        'efficiency': len(alice_sifted_key) / length if length > 0 else 0.0,
        'keys_match': keys_match,
        'error_rate': error_rate,
        'secure': keys_match and error_rate <= 0.11
    }
    
    print(f"Protocol Status: {'SUCCESS' if keys_match else 'FAILED'}")
    print(f"Original length: {length} bits")
    print(f"Final key length: {len(alice_sifted_key)} bits")
    print(f"Efficiency: {protocol_dict['efficiency']:.1%}")
    print(f"Error rate: {error_rate:.1%}")
    print(f"Security status: {'SECURE' if protocol_dict['secure'] else 'COMPROMISED'}")
    
    return protocol_dict, alice_sifted_key, bob_sifted_key

def save_protocol_results(protocol_dict: Dict, alice_key: str, filename: str = "bb84_results.txt"):
    with open(filename, 'w') as f:
        if protocol_dict['keys_match']:
            f.write(f"{''.join(map(str, alice_key))}\n")
        for key, value in protocol_dict.items():
            if isinstance(value, list) and len(value) > 20:
                f.write(f"{key}: [length={len(value)}] {value[:10]}...\n")
            else:
                f.write(f"{key}: {value}\n")
        

def generate_hash_from_key(key: List[int]) -> str:
    key_string = ''.join(map(str, key))
    return hashlib.sha256(key_string.encode()).hexdigest()

if __name__ == "__main__":
    protocol_dict, alice_final_key, bob_final_key = run_bb84_protocol(64)
    
    print(f"\nAlice final key: {''.join(map(str, alice_final_key[:20]))}{'...' if len(alice_final_key) > 20 else ''}")
    print(f"Bob final key:   {''.join(map(str, bob_final_key[:20]))}{'...' if len(bob_final_key) > 20 else ''}")
    
    if protocol_dict['keys_match']:
        key_hash = generate_hash_from_key(alice_final_key)
        print(f"Key hash SHA256: {key_hash[:32]}...")
        save_protocol_results(protocol_dict, alice_key = alice_final_key)
    else:
        print(f"\nProtocol failed - keys do not match!")