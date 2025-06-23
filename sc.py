# sc.py
import os
from pathlib import Path
import json
import sys

# --- Configuration: TIGHTENED FOR CORE APP LOGIC ANALYSIS ---
try:
    SCRIPT_PATH = Path(__file__).resolve()
    PROJECT_ROOT = SCRIPT_PATH.parent
except NameError:
    # This block is a fallback for environments where __file__ might not be defined.
    # Your manual path is likely correct for your specific dev setup.
    PROJECT_ROOT = Path('/mnt/c/Users/remik/Desktop/Code/Dev/notepado/v1.1/noirnote').resolve()

# Give the output a specific, clear name.
OUTPUT_FILENAME = "core_logic_snapshot.txt"

# --- Define Absolute Paths to Exclude ---
# This logic is good. It correctly identifies and excludes the virtual environment.
# Make sure 'VENV_NAME' matches your actual venv folder name.
VENV_NAME = "notepado2" 
VENV_PATH_ABS = (PROJECT_ROOT / VENV_NAME).resolve()

# This set of absolute paths to exclude is perfect. No changes needed here.
EXCLUDED_PATHS_ABS = {
    str((PROJECT_ROOT / ".git").resolve()),
    str(VENV_PATH_ABS),
    str((PROJECT_ROOT / ".vscode").resolve()),
    str((PROJECT_ROOT / ".idea").resolve()),
}

# This list of directory names to ignore is also good. We'll keep it.
EXCLUDED_DIR_NAMES = {
    "__pycache__",
    "site-packages",
    "node_modules",
    "build",
    "dist",
    "release",
    "functions",
    "app/tests"  # <<< NEW: Exclude the tests directory; it's not core app logic.
}

# --- !! CRITICAL CHANGE !! ---
# Restrict included extensions to ONLY the Python source and essential JSON configs.
# We are removing .md, .txt, .gitignore, etc., as they don't define the app's runtime behavior.
INCLUDED_EXTENSIONS = {
    '.sh',
    '.py'
}

# --- !! CRITICAL CHANGE !! ---
# Refine the list of excluded files. We need to be more aggressive here.
# Exclude all package management and non-essential JSON files.
EXCLUDED_FILES = {
    OUTPUT_FILENAME,
    "sc.py",  # Exclude the script itself
    ".DS_Store",
    "Thumbs.db",
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "firebase.json", # Firebase CLI config, not app logic.
    "functions/package.json", # Redundant given the folder exclusion, but safe.
    "functions/package-lock.json",
    "test_api_key_retrieval.py", # Utility script.
    "resources/app_settings.json", # This contains user-specific state, not core logic.
                                   # We want to analyze the code that *uses* this, not the data itself.
    # Exclude other non-essential JSON files if they exist
    # For example: ".eslintrc.js", "tsconfig.json", "tsconfig.dev.json" are for linting/TS, not the Python app.
}
# --- End Configuration Changes ---


def save_project_files(output_file_path):
    """
    Saves relevant project source and config files from the PROJECT_ROOT
    to the output_file_path, applying stricter exclusion rules.
    (The rest of your function logic is excellent and requires no changes)
    """
    file_contents = {}
    print("-" * 30)
    print(f"Project Root: {PROJECT_ROOT}")
    if not PROJECT_ROOT.exists() or not PROJECT_ROOT.is_dir():
        print(f"FATAL ERROR: PROJECT_ROOT '{PROJECT_ROOT}' is invalid!")
        sys.exit(1)
    print(f"Scanning for core application logic files...")
    print(f"Included extensions: {INCLUDED_EXTENSIONS}")
    print("-" * 20)

    files_processed_count = 0
    files_included_count = 0

    for root, dirs, files in os.walk(PROJECT_ROOT, topdown=True, onerror=lambda err: print(f"ERROR walking: {err}")):
        root_path = Path(root).resolve()
        root_path_str = str(root_path)

        is_inside_excluded_path = False
        for excluded_abs_path in EXCLUDED_PATHS_ABS:
            if root_path_str == excluded_abs_path or root_path_str.startswith(excluded_abs_path + os.sep):
                dirs[:] = []; files[:] = []
                is_inside_excluded_path = True
                break
        if is_inside_excluded_path: continue

        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIR_NAMES and not (root_path / d).resolve() in EXCLUDED_PATHS_ABS]

        for file in files:
            files_processed_count += 1
            file_path_abs = root_path / file

            if file in EXCLUDED_FILES: continue
            if file_path_abs.suffix.lower() in INCLUDED_EXTENSIONS:
                try:
                    if file_path_abs.stat().st_size > 5 * 1024 * 1024:
                        print(f"    WARNING: Skipping large file (>5MB): {file_path_abs.relative_to(PROJECT_ROOT)}")
                        continue
                    with open(file_path_abs, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    relative_path = str(file_path_abs.relative_to(PROJECT_ROOT))
                    file_contents[relative_path] = content
                    files_included_count += 1
                except Exception as e:
                    print(f"    ERROR reading {file_path_abs.relative_to(PROJECT_ROOT)}: {e}")

    print("-" * 20)
    print(f"Processed {files_processed_count} files total.")
    print(f"Writing {files_included_count} relevant files to {output_file_path}...")
    if not file_contents:
        print("WARNING: No files were found matching the inclusion criteria!")
        return

    try:
        output_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file_path, "w", encoding="utf-8") as outfile:
            for rel_path_str, content in sorted(file_contents.items()):
                outfile.write(f"======== {rel_path_str} ========\n")
                outfile.write(content)
                outfile.write("\n\n")
        print("Snapshot saved successfully.")
    except Exception as e:
        print(f"ERROR writing output file: {e}")


if __name__ == "__main__":
    output_path = PROJECT_ROOT / OUTPUT_FILENAME
    save_project_files(output_path)