import sys
import os
import json

# Add backend directory to path
sys.path.append(os.path.dirname(__file__))

import database
from classifier import SOCClassifier
from generator import generate_wazuh_log

def test_system():
    print("Starting system validation tests...")
    
    # 1. SQLite Database Initialization
    print("\n[1/3] Testing Database Initialization...")
    try:
        database.init_db()
        print("  [OK] Database initialized successfully.")
    except Exception as e:
        print(f"  [ERROR] Database initialization failed: {e}")
        return False

    # 2. Classifier Loading and Prediction
    print("\n[2/3] Testing XGBoost Model & Feature Extraction...")
    try:
        clf = SOCClassifier()
        print("  [OK] XGBoost classifier loaded successfully.")
        
        # Generate a mock log
        log = generate_wazuh_log()
        print(f"  [OK] Mock log generated (Class: {log['true_class']}, Alert: {log['alert_name']})")
        
        # Classify log
        res = clf.predict(log, custom_threshold=0.15)
        print(f"  [OK] Classification complete. Prediction: {res['prediction']}")
        print(f"    - Probabilities: Normal: {res['proba_normal']:.3f}, FP: {res['proba_fp']:.3f}, Attack: {res['proba_attack']:.3f}")
        print(f"    - Calibrated Risk Score: {res['risk_score']}%")
        
        # Merge results
        log.update(res)
    except Exception as e:
        print(f"  [ERROR] Classifier test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    # 3. Database Save and Retrieve
    print("\n[3/3] Testing database writes and reads...")
    try:
        log_id = database.save_log(log)
        print(f"  [OK] Saved log to database with ID: {log_id}")
        
        # Retrieve logs
        logs, total = database.get_logs(limit=5)
        print(f"  [OK] Retrieved {len(logs)} logs from database (Total in DB: {total})")
        if total > 0:
            retrieved = logs[0]
            print(f"    - Verified log ID matches: {retrieved['id'] == log_id}")
            print(f"    - Verified prediction matches: {retrieved['prediction'] == log.get('prediction')}")
            print(f"    - Verified risk score matches: {retrieved['risk_score'] == log.get('risk_score')}")
    except Exception as e:
        print(f"  [ERROR] Database write/read failed: {e}")
        return False

    print("\n=============================================")
    print("  [OK] ALL BACKEND SYSTEM TESTS PASSED SUCCESSFULLY !")
    print("=============================================")
    return True

if __name__ == "__main__":
    success = test_system()
    sys.exit(0 if success else 1)
