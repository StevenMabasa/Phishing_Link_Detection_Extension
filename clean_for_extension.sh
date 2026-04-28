#!/bin/bash

# Clean script to prepare directory for browser extension
# This removes all Python cache files and other problematic files

echo "Cleaning directory for browser extension..."

# Remove Python cache files
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "*.pyo" -delete 2>/dev/null || true
find . -name "*.pyd" -delete 2>/dev/null || true

# Remove other problematic files
find . -name "*.tmp" -delete 2>/dev/null || true
find . -name "*.temp" -delete 2>/dev/null || true

# Set environment variable to prevent Python cache creation
export PYTHONDONTWRITEBYTECODE=1

echo "✅ Directory cleaned for browser extension"
echo "✅ Python cache creation disabled"
echo ""
echo "You can now load the extension in your browser!"
echo "Directory: $(pwd)"
