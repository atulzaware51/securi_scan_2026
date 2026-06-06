import sys

print("--- STARTING SYSTEM VERIFICATION ---")

# 1. Test Library Installation
try:
    import mysql.connector
    import pandas as pd
    print("✅ Success: 'mysql-connector-python' and 'pandas' are correctly installed!")
except ModuleNotFoundError as e:
    print(f"❌ Error: Library installation check failed. Missing: {e}")
    print("Please run: python -m pip install mysql-connector-python pandas")
    sys.exit(1)

# 2. Test Connection to XAMPP MySQL
try:
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password=""
    )
    print("✅ Success: Python successfully connected to your XAMPP MySQL Server!")
    db.close()
except mysql.connector.Error as err:
    print(f"❌ Error: Database connection failed: {err}")
    print("Make sure your XAMPP Control Panel has 'MySQL' started and running.")
    sys.exit(1)

print("\n🎉 ALL CHECKS PASSED! You are fully cleared to run the Kaggle importer.")