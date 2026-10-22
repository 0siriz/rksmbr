#!/usr/bin/env python3
"""
Unified Pre-MPC ZK Gatekeeping + One-Hot Vector MP-SPDZ Pipeline
Combines:
1. BBS+ Zero-Knowledge Eligibility Pre-Phase (Selective Disclosure of is_over_18)
2. Cryptographic Binding: Fiat-Shamir integration to prevent in-transit ballot tampering
3. One-Hot Vector Ballot Representation: v = [b_1, ..., b_k]
4. Ideal World Tally vs Real Distributed MP-SPDZ Execution
"""

import os
import time
import hmac
import secrets
import hashlib
import json
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Any

# ==============================================================================
# HELPER FUNCTIONS 
# ==============================================================================

def create_one_hot_vote(choice: int, k: int) -> List[int]:
    """Creates a One-Hot vector v = [b_1, ..., b_k] where sum(b_i) == 1."""
    vote = [0] * k
    vote[choice] = 1
    return vote

def ideal_tally_votes(votes: List[List[int]], k: int) -> List[int]:
    """Ideal world tallying function (baseline computation in plaintext)."""
    tally = [0] * k
    for vote in votes:
        for i in range(k):
            tally[i] += vote[i]
    return tally

def vote_percentages(tally: List[int], m: int, k: int) -> List[float]:
    """Computes the percentage of valid votes for each candidate."""
    if m == 0:
        return [0.0] * k
    return [round((tally[i] / m) * 100, 2) for i in range(k)]

# ==============================================================================
# ZERO-KNOWLEDGE PRE-PHASE (BBS+ CREDENTIAL MODEL)
# ==============================================================================

@dataclass
class BBSCredential:
    voter_secret: str
    national_id: str
    is_over_18: bool
    election_id: str
    signature: str

@dataclass
class BBSSelectiveDisclosureProof:
    blinding_nonce: str
    nullifier: int
    disclosed_is_over_18: bool
    disclosed_election_id: str
    zk_proof_token: str
    ballot_digest: str  # Cryptographic digest of the ballot bound to the proof
    _blinded_commitment: bytes

class TrustedIssuer:
    """Issues BBS+ credentials with pre-computed eligibility ('is_over_18')."""
    def __init__(self):
        self._secret_key = secrets.token_bytes(32)
        self.public_id = hashlib.sha256(self._secret_key).hexdigest()[:16]

    def issue_credential(self, national_id: str, age: int, election_id: str) -> BBSCredential:
        voter_secret = secrets.token_hex(16)
        is_over_18 = (age >= 18)
        payload = f"{voter_secret}|{national_id}|{is_over_18}|{election_id}".encode()
        signature = hmac.new(self._secret_key, payload, hashlib.sha256).hexdigest()
        return BBSCredential(voter_secret, national_id, is_over_18, election_id, signature)

    def verify_blinded_signature(
        self, commitment: bytes, zk_proof_token: str, nonce: str, ballot_digest: str
    ) -> bool:
        """Verifies the ZK proof token matches the signature, nonce, and ballot digest."""
        expected_sig = hmac.new(self._secret_key, commitment, hashlib.sha256).hexdigest()
        expected_zk = hashlib.sha256(f"{expected_sig}|{nonce}|{ballot_digest}".encode()).hexdigest()
        return hmac.compare_digest(expected_zk, zk_proof_token)

class VoterClient:
    """Generates the ZK Selective Disclosure proof bound to the One-Hot vote."""
    def __init__(self, credential: BBSCredential, candidate_choice: int, k_candidates: int):
        self.credential = credential
        self.one_hot_vote = create_one_hot_vote(candidate_choice, k_candidates)

    def derive_nullifier(self) -> int:
        digest = hashlib.sha256(
            f"{self.credential.voter_secret}:{self.credential.election_id}".encode()
        ).hexdigest()
        return int(digest[:8], 16)

    def generate_submission(self, tamper_ballot: bool = False) -> Dict[str, Any]:
        blinding_nonce = secrets.token_hex(16)
        nullifier = self.derive_nullifier()
        witness = (
            f"{self.credential.voter_secret}|"
            f"{self.credential.national_id}|"
            f"{self.credential.is_over_18}|"
            f"{self.credential.election_id}"
        ).encode()
        
        # Calculate cryptographic digest of the One-Hot vector
        ballot_bytes = json.dumps(self.one_hot_vote).encode()
        ballot_digest = hashlib.sha256(ballot_bytes).hexdigest()

        # Fiat-Shamir binding: sealing the signature, nonce, and ballot together
        zk_proof_token = hashlib.sha256(
            f"{self.credential.signature}|{blinding_nonce}|{ballot_digest}".encode()
        ).hexdigest()

        proof = BBSSelectiveDisclosureProof(
            blinding_nonce=blinding_nonce,
            nullifier=nullifier,
            disclosed_is_over_18=self.credential.is_over_18,
            disclosed_election_id=self.credential.election_id,
            zk_proof_token=zk_proof_token,
            ballot_digest=ballot_digest,
            _blinded_commitment=witness
        )
        
        submitted_vote = list(self.one_hot_vote)
        if tamper_ballot:
            # Simulate an attacker flipping the ballot bits in transit
            submitted_vote.reverse()

        return {
            "zk_proof": proof,
            "one_hot_vote": submitted_vote
        }

class PreMPCGateway:
    """Verifies ZK proofs, checks ballot integrity, and admits valid votes to MP-SPDZ."""
    def __init__(self, issuer: TrustedIssuer, expected_election_id: str):
        self.issuer = issuer
        self.expected_election_id = expected_election_id

    def verify(self, submission: Dict[str, Any]) -> bool:
        proof: BBSSelectiveDisclosureProof = submission["zk_proof"]
        one_hot_vote = submission["one_hot_vote"]

        # 1. Election context check
        if proof.disclosed_election_id != self.expected_election_id:
            return False
            
        # 2. Tamper detection: verify the ballot matches the cryptographic digest
        computed_digest = hashlib.sha256(json.dumps(one_hot_vote).encode()).hexdigest()
        if computed_digest != proof.ballot_digest:
            return False

        # 3. ZK signature validation over the bound payload
        if not self.issuer.verify_blinded_signature(
            proof._blinded_commitment, proof.zk_proof_token, proof.blinding_nonce, proof.ballot_digest
        ):
            return False
            
        # 4. Age verification check
        return proof.disclosed_is_over_18 is True

# ==============================================================================
# MAIN EXPERIMENT
# ==============================================================================

def main():
    N_SERVERS = 3        # Number of MPC computing nodes (semi-party.x)
    M_TOTAL_USERS = 100  # Total citizens attempting to vote
    K_CANDIDATES = 4     # Number of candidates
    ELECTION_ID = "AAU_EVOTING_2026"
    MPC_PROGRAM = "onehot_voting"

    print(f"Configuration: N_SERVERS={N_SERVERS}, M_TOTAL_USERS={M_TOTAL_USERS}, K_CANDIDATES={K_CANDIDATES}")
    issuer = TrustedIssuer()
    gateway = PreMPCGateway(issuer, ELECTION_ID)

    submissions = []
    for i in range(M_TOTAL_USERS):
        age = 16 if (i % 10 == 0) else secrets.randbelow(50) + 18
        cred = issuer.issue_credential(f"DK-ID-{i:04d}", age, ELECTION_ID)
        choice = secrets.randbelow(K_CANDIDATES)
        client = VoterClient(cred, choice, K_CANDIDATES)
        
        # Introduce a MITM attack simulation for user 1 (tampered ballot)
        tamper = (i == 1)
        submissions.append(client.generate_submission(tamper_ballot=tamper))

    start_zk = time.perf_counter()
    admitted_one_hot_votes = []
    rejected_count = 0
    
    for idx, sub in enumerate(submissions):
        if gateway.verify(sub):
            admitted_one_hot_votes.append(sub["one_hot_vote"])
        else:
            rejected_count += 1
            if idx == 1:
                print("[SECURITY ALERT] MitM attack detected and blocked on Voter 1 (tampered ballot).")
                
    zk_elapsed_ms = (time.perf_counter() - start_zk) * 1000.0
    m_admitted = len(admitted_one_hot_votes)

    print(f"\n--- PRE-MPC ZK GATEWAY ---")
    print(f"Total submissions: {M_TOTAL_USERS} | Admitted adults: {m_admitted} | Rejected: {rejected_count}")
    print(f"Total ZK Verification Time: {zk_elapsed_ms:.2f} ms")

    print("\n--- IDEAL WORLD BASELINE ---")
    ideal_tally = ideal_tally_votes(admitted_one_hot_votes, K_CANDIDATES)
    ideal_pct = vote_percentages(ideal_tally, m_admitted, K_CANDIDATES)
    print(f"Ideal World Tally:       {ideal_tally}")
    print(f"Ideal World Percentages: {ideal_pct}%")

    os.makedirs("Player-Data", exist_ok=True)
    input_file = "Player-Data/Input-P0-0"
    with open(input_file, "w") as f:
        for vec in admitted_one_hot_votes:
            f.write(" ".join(map(str, vec)) + "\n")

    print("\n--- REAL MP-SPDZ DISTRIBUTED EXECUTION ---")
    # Calling compilation with proper parameters
    compile_cmd = ["./compile.py", MPC_PROGRAM, str(m_admitted), str(K_CANDIDATES)]
    subprocess.run(compile_cmd, check=True)

    # Executing the semi-honest protocol
    run_cmd = ["./Scripts/semi.sh", f"{MPC_PROGRAM}-{m_admitted}-{K_CANDIDATES}", "-N", str(N_SERVERS)]
    subprocess.run(run_cmd, check=True)

if __name__ == "__main__":
    main()