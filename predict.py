#!/usr/bin/env python3
"""
predict_url_with_features.py

Builds the numeric features your saved preprocessor expects from a single URL,
then runs the preprocessor + LightGBM booster in the saved bundle to return
a probability and a PHISHING/LEGIT verdict.

Usage:
    python predict_url_with_features.py --bundle path/to/final_model_bundle.pkl --url "http://..." [--threshold 0.5]
"""
import argparse
import joblib
import math
import re
from collections import Counter
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import sys

# ----- list of features your preprocessor expects (from your error message) -----
FEATURE_COLUMNS = [
 'url_length',
 'number_of_dots_in_url',
 'having_repeated_digits_in_url',
 'number_of_digits_in_url',
 'number_of_special_char_in_url',
 'number_of_hyphens_in_url',
 'number_of_underline_in_url',
 'number_of_slash_in_url',
 'number_of_questionmark_in_url',
 'number_of_equal_in_url',
 'number_of_at_in_url',
 'number_of_dollar_in_url',
 'number_of_exclamation_in_url',
 'number_of_hashtag_in_url',
 'number_of_percent_in_url',
 'domain_length',
 'number_of_dots_in_domain',
 'number_of_hyphens_in_domain',
 'having_special_characters_in_domain',
 'number_of_special_characters_in_domain',
 'having_digits_in_domain',
 'number_of_digits_in_domain',
 'having_repeated_digits_in_domain',
 'number_of_subdomains',
 'having_dot_in_subdomain',
 'having_hyphen_in_subdomain',
 'average_subdomain_length',
 'average_number_of_dots_in_subdomain',
 'average_number_of_hyphens_in_subdomain',
 'having_special_characters_in_subdomain',
 'number_of_special_characters_in_subdomain',
 'having_digits_in_subdomain',
 'number_of_digits_in_subdomain',
 'having_repeated_digits_in_subdomain',
 'having_path',
 'path_length',
 'having_query',
 'having_fragment',
 'having_anchor',
 'entropy_of_url',
 'entropy_of_domain'
]

# ----- helper feature functions -----
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    cnt = Counter(s)
    length = len(s)
    ent = 0.0
    for c, freq in cnt.items():
        p = freq / length
        ent -= p * math.log2(p)
    return float(ent)

def count_digits(s: str) -> int:
    return sum(ch.isdigit() for ch in s)

def has_repeated_digit_anywhere(s: str) -> int:
    # True if any digit appears more than once
    digits = [ch for ch in s if ch.isdigit()]
    if not digits:
        return 0
    c = Counter(digits)
    return int(any(v > 1 for v in c.values()))

def count_special_chars(s: str) -> int:
    # count characters that are not alphanumeric (letters/digits)
    return sum(1 for ch in s if not ch.isalnum())

def safe_len(x):
    return 0 if x is None else len(x)

def extract_domain_parts(hostname: str):
    if not hostname:
        return []
    parts = hostname.split('.')
    return parts

def compute_subdomain_stats(hostname: str):
    if not hostname:
        return {
            "number_of_subdomains": 0,
            "having_dot_in_subdomain": 0,
            "having_hyphen_in_subdomain": 0,
            "average_subdomain_length": 0.0,
            "average_number_of_dots_in_subdomain": 0.0,
            "average_number_of_hyphens_in_subdomain": 0.0,
            "having_special_characters_in_subdomain": 0,
            "number_of_special_characters_in_subdomain": 0,
            "having_digits_in_subdomain": 0,
            "number_of_digits_in_subdomain": 0,
            "having_repeated_digits_in_subdomain": 0
        }
    parts = hostname.split('.')
    # assume last two parts are domain + tld (not perfect for some ccTLDs, but reasonable)
    if len(parts) <= 2:
        subdomains = []
    else:
        subdomains = parts[:-2]
    n_sub = len(subdomains)
    if n_sub == 0:
        return {
            "number_of_subdomains": 0,
            "having_dot_in_subdomain": 0,
            "having_hyphen_in_subdomain": 0,
            "average_subdomain_length": 0.0,
            "average_number_of_dots_in_subdomain": 0.0,
            "average_number_of_hyphens_in_subdomain": 0.0,
            "having_special_characters_in_subdomain": 0,
            "number_of_special_characters_in_subdomain": 0,
            "having_digits_in_subdomain": 0,
            "number_of_digits_in_subdomain": 0,
            "having_repeated_digits_in_subdomain": 0
        }
    lengths = [len(s) for s in subdomains]
    hyphen_counts = [s.count('-') for s in subdomains]
    dot_counts = [s.count('.') for s in subdomains]  # each should be 0 normally
    special_counts = [count_special_chars(s) for s in subdomains]
    digit_counts = [count_digits(s) for s in subdomains]
    repeated_digit_flags = [has_repeated_digit_anywhere(s) for s in subdomains]

    return {
        "number_of_subdomains": n_sub,
        "having_dot_in_subdomain": int(any('.' in s for s in subdomains)),
        "having_hyphen_in_subdomain": int(any('-' in s for s in subdomains)),
        "average_subdomain_length": float(sum(lengths) / n_sub),
        "average_number_of_dots_in_subdomain": float(sum(dot_counts) / n_sub),
        "average_number_of_hyphens_in_subdomain": float(sum(hyphen_counts) / n_sub),
        "having_special_characters_in_subdomain": int(any(sc > 0 for sc in special_counts)),
        "number_of_special_characters_in_subdomain": int(sum(special_counts)),
        "having_digits_in_subdomain": int(any(dc > 0 for dc in digit_counts)),
        "number_of_digits_in_subdomain": int(sum(digit_counts)),
        "having_repeated_digits_in_subdomain": int(any(repeated_digit_flags))
    }

# ----- build feature vector for a single URL -----
def build_features_from_url(url: str) -> dict:
    # ensure scheme exists for urlparse to populate hostname properly
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    parsed = urlparse(url_to_parse)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    # anchor: treat anchor as fragment presence (your pipeline had both; we'll set both flags)
    anchor_present = 1 if fragment else 0

    # url-level
    url_str = url_to_parse
    url_len = len(url_str)
    number_of_dots_in_url = url_str.count('.')
    repeated_digits_in_url = has_repeated_digit_anywhere(url_str)
    number_of_digits_in_url = count_digits(url_str)
    number_of_special_char_in_url = count_special_chars(url_str)
    number_of_hyphens_in_url = url_str.count('-')
    number_of_underline_in_url = url_str.count('_')
    number_of_slash_in_url = url_str.count('/')
    number_of_questionmark_in_url = url_str.count('?')
    number_of_equal_in_url = url_str.count('=')
    number_of_at_in_url = url_str.count('@')
    number_of_dollar_in_url = url_str.count('$')
    number_of_exclamation_in_url = url_str.count('!')
    number_of_hashtag_in_url = url_str.count('#')
    number_of_percent_in_url = url_str.count('%')

    # domain-level
    domain = hostname
    domain_length = len(domain)
    number_of_dots_in_domain = domain.count('.')
    number_of_hyphens_in_domain = domain.count('-')
    # special chars in domain (non-alnum and not dot/hyphen)
    number_of_special_characters_in_domain = sum(1 for ch in domain if not (ch.isalnum() or ch in ['.', '-']))
    having_special_characters_in_domain = int(number_of_special_characters_in_domain > 0)
    having_digits_in_domain = int(any(ch.isdigit() for ch in domain))
    number_of_digits_in_domain = sum(1 for ch in domain if ch.isdigit())
    having_repeated_digits_in_domain = has_repeated_digit_anywhere(domain)

    sub_stats = compute_subdomain_stats(domain)

    # path/query/fragment flags
    having_path = int(bool(path and path != '/'))
    path_length = len(path)
    having_query = int(bool(query))
    having_fragment = int(bool(fragment))

    entropy_of_url = shannon_entropy(url_str)
    entropy_of_domain = shannon_entropy(domain)

    feat = {
        'url_length': int(url_len),
        'number_of_dots_in_url': int(number_of_dots_in_url),
        'having_repeated_digits_in_url': int(repeated_digits_in_url),
        'number_of_digits_in_url': int(number_of_digits_in_url),
        'number_of_special_char_in_url': int(number_of_special_char_in_url),
        'number_of_hyphens_in_url': int(number_of_hyphens_in_url),
        'number_of_underline_in_url': int(number_of_underline_in_url),
        'number_of_slash_in_url': int(number_of_slash_in_url),
        'number_of_questionmark_in_url': int(number_of_questionmark_in_url),
        'number_of_equal_in_url': int(number_of_equal_in_url),
        'number_of_at_in_url': int(number_of_at_in_url),
        'number_of_dollar_in_url': int(number_of_dollar_in_url),
        'number_of_exclamation_in_url': int(number_of_exclamation_in_url),
        'number_of_hashtag_in_url': int(number_of_hashtag_in_url),
        'number_of_percent_in_url': int(number_of_percent_in_url),
        'domain_length': int(domain_length),
        'number_of_dots_in_domain': int(number_of_dots_in_domain),
        'number_of_hyphens_in_domain': int(number_of_hyphens_in_domain),
        'having_special_characters_in_domain': int(having_special_characters_in_domain),
        'number_of_special_characters_in_domain': int(number_of_special_characters_in_domain),
        'having_digits_in_domain': int(having_digits_in_domain),
        'number_of_digits_in_domain': int(number_of_digits_in_domain),
        'having_repeated_digits_in_domain': int(having_repeated_digits_in_domain),
        # subdomain stats expanded
        'number_of_subdomains': int(sub_stats['number_of_subdomains']),
        'having_dot_in_subdomain': int(sub_stats['having_dot_in_subdomain']),
        'having_hyphen_in_subdomain': int(sub_stats['having_hyphen_in_subdomain']),
        'average_subdomain_length': float(sub_stats['average_subdomain_length']),
        'average_number_of_dots_in_subdomain': float(sub_stats['average_number_of_dots_in_subdomain']),
        'average_number_of_hyphens_in_subdomain': float(sub_stats['average_number_of_hyphens_in_subdomain']),
        'having_special_characters_in_subdomain': int(sub_stats['having_special_characters_in_subdomain']),
        'number_of_special_characters_in_subdomain': int(sub_stats['number_of_special_characters_in_subdomain']),
        'having_digits_in_subdomain': int(sub_stats['having_digits_in_subdomain']),
        'number_of_digits_in_subdomain': int(sub_stats['number_of_digits_in_subdomain']),
        'having_repeated_digits_in_subdomain': int(sub_stats['having_repeated_digits_in_subdomain']),
        # path/query/fragment
        'having_path': int(having_path),
        'path_length': int(path_length),
        'having_query': int(having_query),
        'having_fragment': int(having_fragment),
        'having_anchor': int(anchor_present),
        # entropy
        'entropy_of_url': float(entropy_of_url),
        'entropy_of_domain': float(entropy_of_domain)
    }

    # Ensure we return columns in the same order/keys your preprocessor expects
    return {col: feat.get(col, 0) for col in FEATURE_COLUMNS}

# ----- prediction wrapper -----
def predict_single_url(bundle_path: str, url: str, threshold: float = 0.5, verbose: bool = True):
    # load bundle
    bundle = joblib.load(bundle_path)
    if 'preprocessor' not in bundle or 'booster' not in bundle:
        raise ValueError("Bundle must contain 'preprocessor' and 'booster' keys")

    preproc = bundle['preprocessor']
    bst = bundle['booster']
    best_iter = bundle.get('best_iteration', None) or None
    calibrator = bundle.get('calibrator', None)

    # build features
    feat_dict = build_features_from_url(url)
    df = pd.DataFrame([feat_dict], columns=FEATURE_COLUMNS)  # explicit columns order
    # transform & predict
    try:
        X_t = preproc.transform(df)
    except Exception as e:
        raise RuntimeError(f"Preprocessor.transform failed. Columns we passed: {list(df.columns)}. Error: {e}")

    raw = bst.predict(X_t, num_iteration=best_iter)
    raw = np.asarray(raw).ravel()
    if raw.size != 1:
        raise RuntimeError(f"Expected single probability output but got shape {raw.shape}")
    prob = float(raw[0])
    # apply calibrator if present
    if calibrator is not None:
        try:
            prob = float(calibrator.predict_proba(np.array([[prob]]))[:,1][0])
        except Exception:
            pass
    label = "PHISHING" if prob >= threshold else "LEGIT"
    if verbose:
        print("URL:", url)
        print("Input feature vector (first 10):", {k: feat_dict[k] for k in list(feat_dict)[:10]})
        print(f"Predicted probability (phish) = {prob:.6f}  -> Verdict = {label} (threshold {threshold})")
    return {"url": url, "probability": prob, "label": label, "features": feat_dict}

# ----- CLI -----
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", "-b", required=True, help="Path to final_model_bundle_*.pkl (joblib)")
    parser.add_argument("--url", "-u", required=True, help="URL to classify")
    parser.add_argument("--threshold", "-t", type=float, default=0.5, help="Probability threshold for PHISHING decision")
    args = parser.parse_args()

    try:
        res = predict_single_url(args.bundle, args.url, threshold=args.threshold, verbose=True)
    except Exception as exc:
        print("ERROR:", exc)
        sys.exit(1)
