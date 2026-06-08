import os
import sys
import urllib.request
import zipfile

NODE_URL = "https://nodejs.org/dist/v22.12.0/node-v22.12.0-win-x64.zip"
ZIP_PATH = "node-portable-22.zip"
TARGET_DIR = "E:\\Projets\\ProjectSOC_AI_1\\node-bin"

def main():
    print(f"Downloading Node.js v22.12.0 from {NODE_URL}...")
    try:
        urllib.request.urlretrieve(NODE_URL, ZIP_PATH)
        print("Download complete. Extracting...")
        
        if not os.path.exists(TARGET_DIR):
            os.makedirs(TARGET_DIR)
            
        with zipfile.ZipFile(ZIP_PATH, 'r') as zip_ref:
            zip_ref.extractall(TARGET_DIR)
            
        print("Extraction complete. Cleaning up...")
        if os.path.exists(ZIP_PATH):
            os.remove(ZIP_PATH)
            
        # Verify node.exe exists
        extracted_folder = os.path.join(TARGET_DIR, "node-v22.12.0-win-x64")
        node_exe = os.path.join(extracted_folder, "node.exe")
        if os.path.exists(node_exe):
            print(f"Node.js v22.12.0 installed successfully at: {node_exe}")
            return True
        else:
            print("Warning: node.exe not found in extracted files.")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
