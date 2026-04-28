#!/bin/bash

# Start the local phishing detection model server
# This script installs dependencies and starts the Flask server

echo "Starting Phishing Detection Model Server..."
echo "=========================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in PATH"
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "ERROR: pip3 is not installed or not in PATH"
    exit 1
fi

# Install dependencies if requirements_server.txt exists
if [ -f "requirements_server.txt" ]; then
    echo "Installing Python dependencies..."
    pip3 install -r requirements_server.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
else
    echo "WARNING: requirements_server.txt not found, skipping dependency installation"
fi

# Check if model file exists
if [ ! -f "phish_pipeline_outputs_fixed/final_model.pkl" ]; then
    echo "ERROR: Model file not found at phish_pipeline_outputs_fixed/final_model.pkl"
    echo "Please ensure the model file exists before starting the server"
    exit 1
fi

echo ""
echo "Starting server on http://localhost:5000"
echo "Press Ctrl+C to stop the server"
echo ""

# Start the Flask server
python3 model_server.py
