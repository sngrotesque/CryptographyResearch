# Cryptography Research

⚠ **WARNING: These encryption algorithms are for research purposes only. DO NOT use them in production environments!**  
⚠ **WARNING: These encryption algorithms are for research purposes only. DO NOT use them in production environments!**  
⚠ **WARNING: These encryption algorithms are for research purposes only. DO NOT use them in production environments!**  

**These algorithms are NOT secure! DO NOT use them in production!**  
**These algorithms are NOT secure! DO NOT use them in production!**  
**These algorithms are NOT secure! DO NOT use them in production!**  

---

### Cipher1  
> A test stream cipher with **intentional vulnerabilities**.  
> **Vulnerable to**:  
> - Chosen-plaintext attacks (CPA)  
> - Known-plaintext attacks (KPA)  
> - Full keystream recovery  

---

### FEA (Old)  
> A **non-tested** block cipher algorithm  
> **Potential risks**:  
> - Excessively high linearity  
> - Key recovery via reverse engineering (unverified)  

---

### SSE (SN Stream Encryption)  
> A **non-standard** stream cipher implementation with critical flaws.  
> **Vulnerable to**:  
> - CPA/KPA attacks  
> - Complete keystream recovery (past/future states)  
> **Flaw**: Weak key scheduling allows deriving all keystream states from a single compromised state.  

---

### SDSE (SN Data Stream Encryption)  
> A **standard-but-flawed** stream cipher implementation.  
> **Vulnerable to**:  
> - CPA/KPA attacks  
> - Keystream reversal to original key  
> **Flaw**: Insufficient nonlinearity in state generation enables key recovery from keystream states.  

---

### Key Risks  
1. **Keystream Reversibility**: All variants allow attackers to:  
   - Recover the initial key from partial keystreams.  
   - Decrypt all past/future messages once any state is compromised.  
2. **Academic Use Only**: Designed to demonstrate cryptographic weaknesses, not for real-world protection.  

### Why These Are Unsafe?  
| Algorithm | Critical Flaw | Practical Attack Impact |  
|-----------|--------------|-------------------------|  
| Cipher1   | No key mixing | Trivial keystream recovery |  
| SSE       | Linear state transition | Single state → full compromise |  
| SDSE      | Weak nonlinear ops | Key recovery via algebraic attacks |  

**For real-world applications**, use standardized algorithms like **AES-GCM** or **ChaCha20-Poly1305**.
