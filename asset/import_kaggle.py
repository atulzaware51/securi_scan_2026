import pandas as pd
import mysql.connector
from urllib.parse import urlparse
import time
import os

print("==================================================")
print("   SECURITY PIPELINE: KAGGLE DATA INGESTION       ")
print("==================================================")

CSV_FILE = "malicious_phish.csv"

# Verify file exists
if not os.path.exists(CSV_FILE):
    print(f"❌ Error: Could not find '{CSV_FILE}' in this directory.")
    print("Please make sure the extracted Kaggle file is renamed and placed here.")
    exit()

# 1. Establish XAMPP MySQL Connection
try:
    db_connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="", # Default XAMPP password is empty
        database="threat_db"
    )
    cursor = db_connection.cursor()
except mysql.connector.Error as err:
    print(f"❌ Database Connection Failed: {err}")
    exit()

# 2. Stream and Parse the Large CSV
print(f"Reading '{CSV_FILE}'...")
start_time = time.time()

# Using a chunk iterator prevents Python from consuming all your system RAM
chunk_size = 50000 
total_records = 0

insert_query = """
    INSERT IGNORE INTO kaggle_threat_data (domain, threat_category) 
    VALUES (%s, %s)
"""

def extract_clean_domain(url_string):
    """Cleans up raw URL strings into pure domain names or IPs."""
    url_string = str(url_string).strip()
    if not url_string.startswith(('http://', 'https://')):
        url_string = 'http://' + url_string
    try:
        parsed = urlparse(url_string)
        domain = parsed.netloc or parsed.path
        # Strip port configurations if present
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain.lower()
    except Exception:
        return None

# Loop through chunks of 50k rows at a time
for chunk in pd.read_csv(CSV_FILE, chunksize=chunk_size):
    # Filter out 'benign' entries to keep our blocklist lightweight and malicious-only
    malicious_rows = chunk[chunk['type'] != 'benign'].copy()
    
    if malicious_rows.empty:
        continue
        
    # Extract and clean domains using the helper function
    malicious_rows['cleaned_domain'] = malicious_rows['url'].apply(extract_clean_domain)
    
    # Drop rows that failed parsing or are duplicate domains within this chunk
    malicious_rows.dropna(subset=['cleaned_domain'], inplace=True)
    malicious_rows.drop_duplicates(subset=['cleaned_domain'], inplace=True)
    
    # Map out the exact list of tuple structures required by mysql-connector
    data_to_insert = list(zip(malicious_rows['cleaned_domain'], malicious_rows['type']))
    
    # Perform high-performance batch insertion
    try:
        cursor.executemany(insert_query, data_to_insert)
        db_connection.commit()
        total_records += cursor.rowcount
        print(f"-> Batch processing complete. Total threats logged so far: {total_records}")
    except mysql.connector.Error as batch_err:
        print(f"⚠️ Warning during batch execution: {batch_err}")
        continue

end_time = time.time()
print("\n==================================================")
print("✅ PIPELINE EXECUTION SUCCESSFUL")
print(f"• Total Malicious Signatures Loaded: {total_records}")
print(f"• Ingestion Duration: {round(end_time - start_time, 2)} seconds")
print("==================================================")

cursor.close()
db_connection.close()