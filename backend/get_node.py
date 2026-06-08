import os
import sys
import urllib.request
import zipfile

NODE_URL = "https://nodejs.org/dist/v20.12.2/node-v20.12.2-win-x64.zip"
ZIP_PATH = "node-portable.zip"
TARGET_DIR = "E:\\Projets\\ProjectSOC_AI_1\\node-bin"

def main():
    print(f"Downloading Node.js from {NODE_URL}...")
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
        extracted_folder = os.path.join(TARGET_DIR, "node-v20.12.2-win-x64")
        node_exe = os.path.join(extracted_folder, "node.exe")
        if os.path.exists(node_exe):
            print(f"✓ Node.js installed successfully at: {node_exe}")
            print(f"Adding Node directory to path command: $env:Path += ';{extracted_folder}'")
        else:
            print("✗ Warning: node.exe not found in extracted files.")
            
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    main()
