#!/usr/bin/env python3
"""
Local model server for phishing detection
Receives URL requests from browser extension and returns predictions using the local model
"""

import json
import sys
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import traceback

# Import the prediction function from predict.py
from predict import predict_single_url

app = Flask(__name__)
CORS(app)  # Enable CORS for browser extension requests

# Configuration
MODEL_BUNDLE_PATH = "phish_pipeline_outputs_fixed/final_model.pkl"
THRESHOLD = 0.464  # Optimal threshold from model training

# Check if model file exists
if not os.path.exists(MODEL_BUNDLE_PATH):
    print(f"ERROR: Model file not found at {MODEL_BUNDLE_PATH}")
    print("Please ensure the model file exists in the phish_pipeline_outputs_fixed directory")
    sys.exit(1)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "message": "Model server is running"})

@app.route('/predict', methods=['POST'])
def predict_url():
    """
    Predict if a URL is phishing or legitimate
    Expected JSON payload: {"url": "http://example.com"}
    """
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                "error": "Missing 'url' in request body",
                "status": "error"
            }), 400
        
        url = data['url']
        
        # Validate URL
        if not url or not isinstance(url, str):
            return jsonify({
                "error": "Invalid URL format",
                "status": "error"
            }), 400
        
        print(f"Received prediction request for URL: {url}")
        
        # Get threshold from request or use default
        threshold = data.get('threshold', THRESHOLD)
        
        # Run prediction
        result = predict_single_url(
            bundle_path=MODEL_BUNDLE_PATH,
            url=url,
            threshold=threshold,
            verbose=False  # Don't print to console for API responses
        )
        
        # Format response for browser extension
        response = {
            "url": result["url"],
            "probability": result["probability"],
            "label": result["label"],
            "is_phishing": result["label"] == "PHISHING",
            "confidence": abs(result["probability"] - 0.5) * 2,  # Convert to 0-1 confidence
            "status": "success"
        }
        
        print(f"Prediction result: {result['label']} (probability: {result['probability']:.4f})")
        
        return jsonify(response)
        
    except Exception as e:
        error_msg = f"Prediction failed: {str(e)}"
        print(f"ERROR: {error_msg}")
        print(f"Traceback: {traceback.format_exc()}")
        
        return jsonify({
            "error": error_msg,
            "status": "error"
        }), 500

@app.route('/predict', methods=['GET'])
def predict_url_get():
    """GET endpoint for simple URL prediction (for testing)"""
    url = request.args.get('url')
    if not url:
        return jsonify({
            "error": "Missing 'url' parameter",
            "status": "error"
        }), 400
    
    # Convert GET request to POST format
    data = {"url": url}
    request._json = data
    return predict_url()

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found",
        "status": "error"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error",
        "status": "error"
    }), 500

if __name__ == '__main__':
    print("Starting Phishing Detection Model Server...")
    print(f"Model bundle: {MODEL_BUNDLE_PATH}")
    print(f"Default threshold: {THRESHOLD}")
    print("Server will be available at: http://localhost:5000")
    print("Endpoints:")
    print("  GET  /health - Health check")
    print("  POST /predict - Predict URL (JSON: {\"url\": \"http://example.com\"})")
    print("  GET  /predict?url=http://example.com - Predict URL (GET)")
    print("\nPress Ctrl+C to stop the server")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
