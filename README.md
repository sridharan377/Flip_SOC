# Real-time PII Defense

### Candidate: Sridharan S  

---

## 📌 Challenge Overview
Flixkart, a leading e-commerce platform, faced a **PII data leak** due to unmonitored assets and unsecured logs.  
The objective of this challenge is to **build a PII Detector & Redactor** that prevents fraud incidents by identifying and masking Personally Identifiable Information (PII) in real time.

---

## 🎯 Solution Components
1. **PII Detector & Redactor (Python Script)**  
   - Reads input CSV file (`record_id, Data_json`)  
   - Detects PII (Standalone + Combinatorial rules)  
   - Masks/redacts sensitive values  
   - Appends a new column `is_pii` (`True`/`False`)  
   - Writes results to `redacted_output_Sridharan_S.csv`

2. **Deployment Strategy**  
   A practical architectural approach to deploy the PII detection at scale.

---

## 🔍 PII Detection Rules
### A. Standalone PII
- **Phone Number** → `98XXXXXX10`  
- **Aadhar Number** → `XXXX XXXX 9012`  
- **Passport Number** → `PXXXXXXX`  
- **UPI ID** → `us***@upi`  

### B. Combinatorial PII  
Considered PII only when **two or more appear together**:  
- Full Name  
- Email Address  
- Physical Address (with PIN/street)  
- Device ID / IP Address tied to a user  

### C. Non-PII (Avoid False Positives)  
- Single first name or last name  
- Standalone city/state/pin code  
- Transaction ID / Order ID  
- Any single attribute from List B  

---

## ⚙️ How to Run
```bash
# Run detection
python3 detector_Sridharan_S.py iscp_pii_dataset_-_Sheet1.csv redacted_output_Sridharan_S.csv
