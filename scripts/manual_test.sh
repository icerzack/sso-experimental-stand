#!/bin/bash

# Manual Test Script for SSO Test Stand
# Tests SAML and OIDC flows manually

set -e

SAML_SP_URL="${SAML_SP_URL:-http://saml-sp.localhost}"
OIDC_RP_URL="${OIDC_RP_URL:-http://oidc-rp.localhost}"
USERNAME="${USERNAME:-testuser1}"
PASSWORD="${PASSWORD:-password123}"

echo "=== SSO Manual Test Script ==="
echo ""

test_saml() {
    echo "Testing SAML SP..."
    echo "1. Accessing protected endpoint: ${SAML_SP_URL}/protected"
    
    # Use curl with -L to follow redirects and -v for verbose output
    echo "Redirect chain:"
    curl -L -v "${SAML_SP_URL}/protected" 2>&1 | grep -E "(< HTTP|< Location|> GET)"
    
    echo ""
    echo "2. Checking if user info is displayed..."
    response=$(curl -L -s "${SAML_SP_URL}/protected")
    if echo "$response" | grep -q "$USERNAME"; then
        echo "✓ User info found in response"
    else
        echo "✗ User info not found"
    fi
    
    echo ""
}

test_oidc() {
    echo "Testing OIDC RP..."
    echo "1. Accessing protected endpoint: ${OIDC_RP_URL}/protected"
    
    echo "Redirect chain:"
    curl -L -v "${OIDC_RP_URL}/protected" 2>&1 | grep -E "(< HTTP|< Location|> GET)"
    
    echo ""
    echo "2. Checking for redirect_uri errors..."
    response=$(curl -L -s "${OIDC_RP_URL}/protected")
    if echo "$response" | grep -qi "invalid.*redirect.*uri"; then
        echo "✗ Redirect URI error detected!"
    else
        echo "✓ No redirect URI errors"
    fi
    
    echo ""
    echo "3. Checking if user info is displayed..."
    if echo "$response" | grep -q "$USERNAME"; then
        echo "✓ User info found in response"
    else
        echo "✗ User info not found"
    fi
    
    echo ""
}

test_logout() {
    echo "Testing Logout..."
    
    # Test SAML logout
    echo "1. Testing SAML logout..."
    curl -L -s "${SAML_SP_URL}/logout" > /dev/null
    response=$(curl -L -s "${SAML_SP_URL}/protected")
    if echo "$response" | grep -q "login"; then
        echo "✓ SAML logout successful (redirected to login)"
    else
        echo "✗ SAML logout may have failed"
    fi
    
    echo ""
    
    # Test OIDC logout
    echo "2. Testing OIDC logout..."
    curl -L -s "${OIDC_RP_URL}/logout" > /dev/null
    response=$(curl -L -s "${OIDC_RP_URL}/protected")
    if echo "$response" | grep -q "login"; then
        echo "✓ OIDC logout successful (redirected to login)"
    else
        echo "✗ OIDC logout may have failed"
    fi
    
    echo ""
}

main() {
    echo "Starting manual tests..."
    echo ""
    
    test_saml
    test_oidc
    test_logout
    
    echo "=== Test Complete ==="
    echo ""
    echo "Note: This script tests basic functionality."
    echo "For full authentication flow, use a browser and follow redirects manually."
}

main "$@"

