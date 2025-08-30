#!/usr/bin/env python3
"""
PyPI Build and Upload Script for PostQuantum DualUSB Token Library

This script helps build and upload the package to PyPI with proper checks.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run a command and handle errors."""
    print(f"\n🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"Error: {e.stderr}")
        return None

def check_prerequisites():
    """Check if required tools are installed."""
    print("🔍 Checking prerequisites...")
    
    # Check if build tools are installed
    try:
        import build
        print("✅ python-build is installed")
    except ImportError:
        print("❌ python-build not found. Install with: pip install build")
        return False
    
    try:
        import twine
        print("✅ twine is installed")
    except ImportError:
        print("❌ twine not found. Install with: pip install twine")
        return False
    
    return True

def clean_build_dirs():
    """Clean previous build artifacts."""
    print("\n🧹 Cleaning build directories...")
    for dir_name in ["build", "dist", "*.egg-info"]:
        run_command(f"rm -rf {dir_name}", f"Removing {dir_name}")

def build_package():
    """Build the package."""
    if not run_command("python -m build", "Building package"):
        return False
    
    # List built files
    dist_files = list(Path("dist").glob("*"))
    print(f"\n📦 Built files:")
    for file in dist_files:
        print(f"  - {file.name}")
    
    return True

def check_package():
    """Check the built package."""
    return run_command("python -m twine check dist/*", "Checking package")

def upload_to_test_pypi():
    """Upload to Test PyPI first."""
    print("\n⚠️  Uploading to Test PyPI first...")
    return run_command("python -m twine upload --repository testpypi dist/*", 
                      "Uploading to Test PyPI")

def upload_to_pypi():
    """Upload to production PyPI."""
    print("\n🚀 Uploading to production PyPI...")
    return run_command("python -m twine upload dist/*", "Uploading to PyPI")

def main():
    """Main build and upload process."""
    print("🛡️  PostQuantum DualUSB Token Library - PyPI Build Script")
    print("=" * 60)
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n❌ Prerequisites not met. Please install required tools.")
        sys.exit(1)
    
    # Clean build directories
    clean_build_dirs()
    
    # Build package
    if not build_package():
        print("\n❌ Build failed. Please check errors above.")
        sys.exit(1)
    
    # Check package
    if not check_package():
        print("\n❌ Package check failed. Please fix issues.")
        sys.exit(1)
    
    print("\n✅ Package built and validated successfully!")
    
    # Ask user about upload
    choice = input("\nWhat would you like to do?\n"
                  "1. Upload to Test PyPI\n"
                  "2. Upload to Production PyPI\n"
                  "3. Exit (just build)\n"
                  "Choice (1-3): ").strip()
    
    if choice == "1":
        if upload_to_test_pypi():
            print("\n✅ Successfully uploaded to Test PyPI!")
            print("🔗 Check: https://test.pypi.org/project/pqcdualusb/")
        else:
            print("\n❌ Upload to Test PyPI failed.")
    
    elif choice == "2":
        confirm = input("\n⚠️  Are you sure you want to upload to production PyPI? (yes/no): ")
        if confirm.lower() == "yes":
            if upload_to_pypi():
                print("\n🎉 Successfully uploaded to production PyPI!")
                print("🔗 Check: https://pypi.org/project/pqcdualusb/")
            else:
                print("\n❌ Upload to PyPI failed.")
        else:
            print("Upload cancelled.")
    
    else:
        print("\n📦 Build completed. Package files are in dist/")

if __name__ == "__main__":
    main()
