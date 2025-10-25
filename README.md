# MITRE ATT&CK ETL Data Connector

**Author:** [Your Name Here]  
**Roll Number:** [Your Roll Number Here]  
**Course:** Software Architecture  
**Institution:** SSN College of Engineering (Kyureeus EdTech Program)

---

## 📋 Project Overview

This project implements a complete **ETL (Extract, Transform, Load)** pipeline that connects to the MITRE ATT&CK framework to extract cyber threat intelligence data, transforms it into a MongoDB-compatible format, and loads it into a database for analysis.

### What is MITRE ATT&CK?

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally recognized knowledge base of cyber adversary behavior. It catalogs tactics and techniques used by threat actors based on real-world observations.

---

## 🎯 Features

- ✅ **Extract:** Downloads STIX 2.1 threat intelligence data from MITRE ATT&CK GitHub repository
- ✅ **Transform:** Converts raw STIX objects into structured MongoDB documents
- ✅ **Load:** Efficiently stores data in MongoDB with proper indexing
- ✅ **Validate:** Provides statistics and verification of loaded data
- ✅ **Error Handling:** Robust exception handling for network and database operations
- ✅ **Secure Configuration:** Uses environment variables for sensitive data
- ✅ **Batch Processing:** Loads data in batches of 1000 for optimal performance

---

## 📊 Data Statistics

Successfully extracted and loaded:
- **Total Documents:** 22,652
- **Attack Patterns:** 823 techniques
- **Malware:** 667 malware families
- **Tools:** 91 tools used by threat actors
- **Threat Groups:** 181 intrusion sets
- **Relationships:** 20,411 relationships between entities
- **Mitigations:** 268 course-of-action recommendations
- **Campaigns:** 47 documented campaigns

---

## 🏗️ Architecture

```
┌─────────────┐      ┌─────────────┐      ┌──────────────┐
│   EXTRACT   │ ───> │  TRANSFORM  │ ───> │     LOAD     │
│  (GitHub)   │      │  (Process)  │      │  (MongoDB)   │
└─────────────┘      └─────────────┘      └──────────────┘
                                                    │
                                                    ▼
                                           ┌──────────────┐
                                           │   VALIDATE   │
                                           └──────────────┘
```

### Pipeline Flow:
1. **Extract:** Fetch raw JSON data from MITRE ATT&CK GitHub repository
2. **Transform:** Parse STIX objects and create MongoDB-compatible documents
3. **Load:** Insert documents into MongoDB with batch processing
4. **Validate:** Count documents, verify data integrity, and display statistics

---

## 📦 Project Structure

```
ASSIGNMENT-2/
├── mitre_taxii_connector.py    # Main ETL script
├── requirements.txt             # Python dependencies
├── .env                         # Environment variables (NOT committed)
├── .gitignore                   # Git ignore rules
├── README.md                    # This file
└── venv/                        # Virtual environment (NOT committed)
```

---

## 🔧 Prerequisites

- **Python:** 3.8 or higher
- **MongoDB:** Community Edition or MongoDB Atlas
- **Internet Connection:** Required to download MITRE ATT&CK data
- **Disk Space:** ~100 MB for data storage

---

## 📥 Installation

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd ASSIGNMENT-2
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables

Create a `.env` file in the project root:

```bash
# GitHub source configuration
REQUEST_TIMEOUT=120
USE_GITHUB_BACKUP=true

# MongoDB Configuration
MONGO_URI=mongodb://localhost:27017/
DB_NAME=etl_database
COLLECTION_NAME=mitre_attack_raw
```

**Note:** For MongoDB Atlas (cloud), use:
```
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/
```

### Step 5: Start MongoDB

Ensure MongoDB is running:
- **Local:** Start MongoDB service
- **Atlas:** Ensure cluster is active and accessible

---

## 🚀 Usage

### Run the ETL Pipeline

```bash
python mitre_taxii_connector.py
```

### Expected Output

```
============================================================
MITRE ATT&CK ETL Pipeline (GitHub Source)
============================================================
✓ Connected to MongoDB: etl_database.mitre_attack_raw

--- EXTRACT Phase ---
Fetching from GitHub: https://raw.githubusercontent.com/...
This may take 2-5 minutes depending on your internet speed...
✓ Download complete, parsing JSON...
✓ Extracted 22652 STIX objects from GitHub

Object type distribution:
  - relationship: 20411
  - attack-pattern: 823
  - malware: 667
  ...

--- TRANSFORM Phase ---
✓ Transformed 22652 documents

--- LOAD Phase ---
  Inserted batch: 1000/22652 documents
  Inserted batch: 2000/22652 documents
  ...
✓ Successfully inserted 22652 documents into MongoDB
Creating indexes...
✓ Created indexes

--- VALIDATION Phase ---
Total documents in collection: 22652
...

✅ ETL Pipeline completed successfully!
```

---

## 📊 MongoDB Schema

### Document Structure

```json
{
  "_id": ObjectId("..."),
  "stix_id": "attack-pattern--970cdb5c-02fb-4c38-b17e-d6327cf3c810",
  "stix_type": "attack-pattern",
  "name": "Command and Scripting Interpreter: PowerShell",
  "description": "Adversaries may abuse PowerShell commands...",
  "created": "2020-03-09T12:23:15.456Z",
  "modified": "2023-04-12T10:15:30.123Z",
  "mitre_attack_id": "T1059.001",
  "mitre_url": "https://attack.mitre.org/techniques/T1059/001",
  "kill_chain_phases": [...],
  "external_references": [...],
  "raw_data": { /* Complete STIX object */ },
  "ingestion_timestamp": ISODate("2025-10-18T10:17:31.035Z"),
  "source": "MITRE ATT&CK GitHub",
  "api_version": "2.1"
}
```

### Indexes Created

- `stix_id` - For unique identification
- `stix_type` - For filtering by object type
- `ingestion_timestamp` - For temporal queries
- `mitre_attack_id` - For technique lookup

---

## 🔍 Querying the Data

### Using MongoDB Compass (GUI)

1. Open MongoDB Compass
2. Connect to `localhost:27017`
3. Navigate to `etl_database` → `mitre_attack_raw`
4. Use the query bar

### Sample Queries

**Find all attack patterns:**
```javascript
{ "stix_type": "attack-pattern" }
```

**Find specific technique:**
```javascript
{ "mitre_attack_id": "T1059.001" }
```

**Find PowerShell-related attacks:**
```javascript
{ "name": /PowerShell/i }
```

**Find recent malware:**
```javascript
{ 
  "stix_type": "malware",
  "modified": { $gte: "2023-01-01" }
}
```

### Using Python (PyMongo)

```python
from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/')
db = client['etl_database']
collection = db['mitre_attack_raw']

# Get all attack patterns
attack_patterns = collection.find({'stix_type': 'attack-pattern'})
for pattern in attack_patterns:
    print(f"{pattern['mitre_attack_id']}: {pattern['name']}")

# Count malware
malware_count = collection.count_documents({'stix_type': 'malware'})
print(f"Total malware: {malware_count}")
```

---

## 🛡️ Security Best Practices

1. ✅ **Environment Variables:** All sensitive data stored in `.env`
2. ✅ **Git Ignore:** `.env` excluded from version control
3. ✅ **No Hardcoded Credentials:** Configuration externalized
4. ✅ **Timeout Handling:** Prevents indefinite hangs
5. ✅ **Error Handling:** Graceful failure with informative messages

---

## 🧪 Testing & Validation

### Automated Validation

The script includes built-in validation:
- Document count verification
- Type distribution analysis
- Sample data display
- Timestamp verification

### Manual Testing Checklist

- [x] Environment variables loaded correctly
- [x] MongoDB connection established
- [x] Data downloaded successfully from GitHub
- [x] All 22,652 documents extracted
- [x] Documents transformed correctly
- [x] Data inserted into MongoDB
- [x] Indexes created successfully
- [x] Validation statistics displayed
- [x] No errors during execution

---

## 📈 Performance Metrics

- **Download Time:** 2-5 minutes (depends on internet speed)
- **Transform Time:** ~30 seconds
- **Load Time:** 1-2 minutes (batch size: 1000)
- **Total Execution Time:** ~5-8 minutes
- **Data Size:** ~50-100 MB in MongoDB
- **Memory Usage:** ~200-300 MB during execution

---

## 🐛 Troubleshooting

### Issue: MongoDB Connection Error

```
✗ MongoDB connection error: [Errno 61] Connection refused
```

**Solution:**
- Ensure MongoDB is running
- Check MongoDB is listening on port 27017
- Verify MONGO_URI in `.env` file

### Issue: Network Timeout

```
✗ Request timeout after 120 seconds
```

**Solution:**
- Check internet connection
- Increase REQUEST_TIMEOUT in `.env`
- Check firewall settings

### Issue: Module Not Found

```
ModuleNotFoundError: No module named 'pymongo'
```

**Solution:**
- Activate virtual environment: `venv\Scripts\activate`
- Install dependencies: `pip install -r requirements.txt`

### Issue: Empty requirements.txt

**Solution:**
- Ensure requirements.txt is not empty (should be ~200 bytes)
- Manually add dependencies as listed in Installation section

---

## 📚 Data Source

**Primary Source:** MITRE ATT&CK GitHub Repository
- **URL:** https://github.com/mitre/cti
- **Data File:** enterprise-attack/enterprise-attack.json
- **Format:** STIX 2.1 JSON
- **Update Frequency:** MITRE updates quarterly
- **License:** Apache License 2.0

---

## 🔄 Future Enhancements

- [ ] Add support for Mobile ATT&CK and ICS ATT&CK
- [ ] Implement incremental updates (only fetch new data)
- [ ] Add data visualization dashboard
- [ ] Implement API endpoints for querying
- [ ] Add scheduling for automatic updates
- [ ] Create Docker container for easy deployment
- [ ] Add unit tests and integration tests
- [ ] Implement logging to file

---

## 📖 References

- [MITRE ATT&CK Official Website](https://attack.mitre.org/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [PyMongo Documentation](https://pymongo.readthedocs.io/)
- [Python dotenv Documentation](https://pypi.org/project/python-dotenv/)

---

## 🤝 Contributing

This is an academic project for SSN College of Engineering. For questions or improvements:
1. Create an issue in the repository
2. Submit a pull request with clear description
3. Contact via WhatsApp group (Kyureeus/SSN College)

---

## 📄 License

This project is for educational purposes as part of the Software Architecture course at SSN College of Engineering.

MITRE ATT&CK data is licensed under Apache License 2.0.

---

## ✉️ Contact

**Student:** [Your Name]  
**Roll Number:** [Your Roll Number]  
**Email:** [Your Email]  
**Course:** Software Architecture  
**Institution:** SSN College of Engineering

---

## 🙏 Acknowledgments

- **MITRE Corporation** for maintaining the ATT&CK framework
- **Kyureeus EdTech** for the learning opportunity
- **SSN College of Engineering** for the course structure
- **Open Source Community** for Python libraries used

---

**Last Updated:** October 18, 2025
**Version:** 1.0.0
**Status:** ✅ Completed and Tested