"""
MITRE ATT&CK GitHub ETL Connector
Author: [Your Name]
Roll Number: [Your Roll Number]

This connector extracts threat intelligence data from MITRE ATT&CK via GitHub,
transforms it into a MongoDB-compatible format, and loads it into a collection.
"""

import os
import json
import requests
from datetime import datetime
from typing import Dict, List, Any
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

class MITREAttackConnector:
    """ETL Connector for MITRE ATT&CK (GitHub Source)"""
    
    def __init__(self):
        """Initialize the connector with configuration"""
        # GitHub URL for MITRE ATT&CK data
        self.github_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.timeout = int(os.getenv('REQUEST_TIMEOUT', '120'))
        
        # MongoDB Configuration
        self.mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
        self.db_name = os.getenv('DB_NAME', 'etl_database')
        self.collection_name = os.getenv('COLLECTION_NAME', 'mitre_attack_raw')
        
        # Initialize MongoDB client
        self.mongo_client = None
        self.db = None
        self.collection = None
        
    def connect_mongodb(self):
        """Establish connection to MongoDB"""
        try:
            self.mongo_client = MongoClient(self.mongo_uri)
            self.db = self.mongo_client[self.db_name]
            self.collection = self.db[self.collection_name]
            print(f"✓ Connected to MongoDB: {self.db_name}.{self.collection_name}")
            return True
        except Exception as e:
            print(f"✗ MongoDB connection error: {str(e)}")
            return False
    
    def extract(self) -> List[Dict[str, Any]]:
        """
        Extract data from MITRE ATT&CK GitHub repository
        Returns: List of STIX objects
        """
        print("\n--- EXTRACT Phase ---")
        extracted_data = []
        
        try:
            print(f"Fetching from GitHub: {self.github_url}")
            print("This may take 2-5 minutes depending on your internet speed...")
            
            response = requests.get(self.github_url, timeout=self.timeout)
            response.raise_for_status()
            
            print("✓ Download complete, parsing JSON...")
            data = response.json()
            extracted_data = data.get('objects', [])
            
            print(f"✓ Extracted {len(extracted_data)} STIX objects from GitHub")
            
            # Display sample object types
            object_types = {}
            for obj in extracted_data:
                obj_type = obj.get('type', 'unknown')
                object_types[obj_type] = object_types.get(obj_type, 0) + 1
            
            print("\nObject type distribution:")
            for obj_type, count in sorted(object_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {obj_type}: {count}")
            
        except requests.Timeout:
            print(f"✗ Request timeout after {self.timeout} seconds")
            print("  Try increasing REQUEST_TIMEOUT in .env file")
            raise
        except requests.RequestException as e:
            print(f"✗ Network error: {str(e)}")
            raise
        except json.JSONDecodeError as e:
            print(f"✗ JSON parsing error: {str(e)}")
            raise
        except Exception as e:
            print(f"✗ Extract error: {str(e)}")
            raise
        
        return extracted_data
    
    def transform(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Transform STIX data for MongoDB compatibility
        Args:
            data: List of raw STIX objects
        Returns: List of transformed documents
        """
        print("\n--- TRANSFORM Phase ---")
        transformed_data = []
        
        try:
            for obj in data:
                # Create a MongoDB-compatible document
                doc = {
                    'stix_id': obj.get('id', ''),
                    'stix_type': obj.get('type', ''),
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'created': obj.get('created', ''),
                    'modified': obj.get('modified', ''),
                    'raw_data': obj,  # Store complete raw data
                    'ingestion_timestamp': datetime.utcnow(),
                    'source': 'MITRE ATT&CK GitHub',
                    'api_version': '2.1'
                }
                
                # Add type-specific fields
                if obj.get('type') == 'attack-pattern':
                    doc['kill_chain_phases'] = obj.get('kill_chain_phases', [])
                    doc['external_references'] = obj.get('external_references', [])
                    
                    # Extract MITRE ATT&CK ID
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            doc['mitre_attack_id'] = ref.get('external_id', '')
                            doc['mitre_url'] = ref.get('url', '')
                
                elif obj.get('type') == 'malware':
                    doc['is_family'] = obj.get('is_family', False)
                    doc['malware_types'] = obj.get('malware_types', [])
                
                elif obj.get('type') == 'tool':
                    doc['tool_types'] = obj.get('tool_types', [])
                
                elif obj.get('type') == 'intrusion-set':
                    doc['aliases'] = obj.get('aliases', [])
                
                elif obj.get('type') == 'campaign':
                    doc['aliases'] = obj.get('aliases', [])
                    doc['first_seen'] = obj.get('first_seen', '')
                    doc['last_seen'] = obj.get('last_seen', '')
                
                transformed_data.append(doc)
            
            print(f"✓ Transformed {len(transformed_data)} documents")
            
        except Exception as e:
            print(f"✗ Transform error: {str(e)}")
            raise
        
        return transformed_data
    
    def load(self, data: List[Dict[str, Any]]) -> bool:
        """
        Load transformed data into MongoDB
        Args:
            data: List of transformed documents
        Returns: Success status
        """
        print("\n--- LOAD Phase ---")
        
        try:
            if not data:
                print("⚠ No data to load")
                return False
            
            # Clear existing data (optional - remove comment if you want to keep old data)
            existing_count = self.collection.count_documents({})
            if existing_count > 0:
                print(f"Found {existing_count} existing documents. Clearing collection...")
                self.collection.delete_many({})
            
            # Insert documents in batches for better performance
            batch_size = 1000
            total_inserted = 0
            
            for i in range(0, len(data), batch_size):
                batch = data[i:i + batch_size]
                result = self.collection.insert_many(batch)
                total_inserted += len(result.inserted_ids)
                print(f"  Inserted batch: {total_inserted}/{len(data)} documents")
            
            print(f"✓ Successfully inserted {total_inserted} documents into MongoDB")
            
            # Create indexes for better query performance
            print("Creating indexes...")
            self.collection.create_index('stix_id')
            self.collection.create_index('stix_type')
            self.collection.create_index('ingestion_timestamp')
            self.collection.create_index('mitre_attack_id')
            print("✓ Created indexes")
            
            return True
            
        except Exception as e:
            print(f"✗ Load error: {str(e)}")
            return False
    
    def validate(self) -> Dict[str, Any]:
        """
        Validate the loaded data
        Returns: Validation statistics
        """
        print("\n--- VALIDATION Phase ---")
        
        try:
            total_docs = self.collection.count_documents({})
            print(f"Total documents in collection: {total_docs}")
            
            # Count by type
            pipeline = [
                {'$group': {'_id': '$stix_type', 'count': {'$sum': 1}}},
                {'$sort': {'count': -1}}
            ]
            type_counts = list(self.collection.aggregate(pipeline))
            
            print("\nDocument counts by STIX type:")
            for item in type_counts:
                print(f"  - {item['_id']}: {item['count']}")
            
            # Get latest ingestion timestamp
            latest = self.collection.find_one(
                sort=[('ingestion_timestamp', -1)]
            )
            if latest:
                print(f"\nLatest ingestion: {latest['ingestion_timestamp']}")
            
            # Sample attack pattern
            attack_pattern = self.collection.find_one({'stix_type': 'attack-pattern'})
            if attack_pattern:
                print(f"\n📋 Sample Attack Pattern:")
                print(f"  ID: {attack_pattern.get('mitre_attack_id', 'N/A')}")
                print(f"  Name: {attack_pattern.get('name', 'N/A')}")
                desc = attack_pattern.get('description', 'N/A')
                print(f"  Description: {desc[:150]}..." if len(desc) > 150 else f"  Description: {desc}")
            
            # Sample malware
            malware = self.collection.find_one({'stix_type': 'malware'})
            if malware:
                print(f"\n🦠 Sample Malware:")
                print(f"  Name: {malware.get('name', 'N/A')}")
                print(f"  Types: {', '.join(malware.get('malware_types', []))}")
            
            return {
                'total_documents': total_docs,
                'type_distribution': type_counts,
                'status': 'success'
            }
            
        except Exception as e:
            print(f"✗ Validation error: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def run_etl(self):
        """Execute the complete ETL pipeline"""
        print("="*60)
        print("MITRE ATT&CK ETL Pipeline (GitHub Source)")
        print("="*60)
        
        try:
            # Connect to MongoDB
            if not self.connect_mongodb():
                raise Exception("Failed to connect to MongoDB")
            
            # Extract
            raw_data = self.extract()
            
            if not raw_data:
                print("⚠ No data extracted. Exiting.")
                return
            
            # Transform
            transformed_data = self.transform(raw_data)
            
            # Load
            load_success = self.load(transformed_data)
            
            if not load_success:
                raise Exception("Failed to load data into MongoDB")
            
            # Validate
            validation_result = self.validate()
            
            print("\n" + "="*60)
            print("✅ ETL Pipeline completed successfully!")
            print("="*60)
            print("\n💡 Next Steps:")
            print("  1. Open MongoDB Compass")
            print("  2. Refresh the collection (F5)")
            print("  3. Explore the data!")
            
        except Exception as e:
            print(f"\n✗ ETL Pipeline failed: {str(e)}")
            print("\n🔍 Troubleshooting:")
            print("  - Check your internet connection")
            print("  - Verify MongoDB is running")
            print("  - Try increasing REQUEST_TIMEOUT in .env")
        
        finally:
            # Close MongoDB connection
            if self.mongo_client:
                self.mongo_client.close()
                print("\n✓ MongoDB connection closed")


def main():
    """Main execution function"""
    connector = MITREAttackConnector()
    connector.run_etl()


if __name__ == "__main__":
    main()