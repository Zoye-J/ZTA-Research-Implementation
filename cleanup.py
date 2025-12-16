#!/usr/bin/env python3
"""
Cleanup script to reset the database
"""
import os
import sys


def cleanup():
    # List of database files to remove
    db_files = [
        "zta.db",
        "government_zta.db",
        "instance/government_zta.db",
        "instance/zta.db",
    ]

    print("Cleaning up database files...")

    for db_file in db_files:
        if os.path.exists(db_file):
            os.remove(db_file)
            print(f"✓ Removed: {db_file}")
        else:
            print(f"  Not found: {db_file}")

    # Remove __pycache__ folders
    print("\nCleaning up Python cache...")
    for root, dirs, files in os.walk("."):
        if "__pycache__" in dirs:
            cache_dir = os.path.join(root, "__pycache__")
            import shutil

            shutil.rmtree(cache_dir, ignore_errors=True)
            print(f"✓ Removed: {cache_dir}")

    print("\n✓ Cleanup complete!")
    print(
        "Run 'python setup_database.py' to recreate the database with government users."
    )


if __name__ == "__main__":
    cleanup()
