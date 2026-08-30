import sys
import os
import io
import cv2
import numpy as np
from PIL import Image

# Ensure stdout handles UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
sys.path.insert(0, backend_dir)

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def make_qr_png_bytes(text: str) -> bytes:
    """Helper to generate a valid QR code PNG image byte array using OpenCV and Pillow."""
    encoder = cv2.QRCodeEncoder.create()
    matrix = encoder.encode(text).astype(np.uint8)
    padded = cv2.copyMakeBorder(matrix, 10, 10, 10, 10, cv2.BORDER_CONSTANT, value=255)
    scaled = cv2.resize(padded, (400, 400), interpolation=cv2.INTER_NEAREST)
    pil_img = Image.fromarray(scaled)
    buf = io.BytesIO()
    pil_img.save(buf, format="PNG")
    return buf.getvalue()

def test_cybershield_suite():
    print("==================================================")
    print("CYBERSHIELD AI — COMPLETE VERIFICATION TEST SUITE")
    print("==================================================")

    # 1. Test Health & Supabase DB Status
    resp = client.get("/health")
    assert resp.status_code == 200
    health_data = resp.json()
    assert "db_connected" in health_data
    print(f"[PASS] Health Check Passed (Status: {health_data['status']}, DB Connected: {health_data['db_connected']})")

    # 2. Test Phishing URL Scan
    url_payload = {"url": "http://192.168.1.1/sbi-kyc-verify-login.xyz"}
    resp = client.post("/api/v1/scan/url", json=url_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] > 65
    assert data["risk_level"] == "SCAM"
    print(f"[PASS] Phishing URL Test Passed (Score: {data['risk_score']}, Classification: {data['risk_level']})")

    # 3. Test Safe URL Scan
    safe_url_payload = {"url": "https://wikipedia.org"}
    resp = client.post("/api/v1/scan/url", json=safe_url_payload)
    assert resp.status_code == 200
    safe_data = resp.json()
    assert safe_data["risk_score"] <= 25
    assert safe_data["risk_level"] == "SAFE"
    print(f"[PASS] Safe URL Test Passed (Score: {safe_data['risk_score']}, Classification: {safe_data['risk_level']})")

    # 4. Test False Positive Prevention (Legitimate Service Notification)
    legit_msg = {"message": "Dear customer, your Jio account plan has expired. Please recharge at https://jio.com/recharge to enjoy uninterrupted services."}
    resp = client.post("/api/v1/scan/message", json=legit_msg)
    assert resp.status_code == 200
    legit_data = resp.json()
    assert legit_data["risk_score"] <= 25
    assert legit_data["risk_level"] == "SAFE"
    print(f"[PASS] False-Positive Reduction Passed (Score: {legit_data['risk_score']}, Classification: {legit_data['risk_level']})")

    # 5. Test Phishing SMS Scan (Urgency + Credential Harvesting + Fake URL)
    phish_msg = {"message": "URGENT! Your bank account will be blocked today due to pending KYC. Verify immediately at http://hdfc-kyc-verify.temp-web.xyz and share OTP."}
    resp = client.post("/api/v1/scan/message", json=phish_msg)
    assert resp.status_code == 200
    msg_data = resp.json()
    assert msg_data["risk_score"] > 65
    assert msg_data["risk_level"] == "SCAM"
    print(f"[PASS] Phishing SMS Test Passed (Score: {msg_data['risk_score']}, Classification: {msg_data['risk_level']})")

    # 6. Test Email Scanner
    email_payload = {
        "subject": "Action Required: Verify Account Credentials",
        "body": "Your bank account access is suspended. Please verify your OTP at http://bank-verify.xyz immediately."
    }
    resp = client.post("/api/v1/scan/email", json=email_payload)
    assert resp.status_code == 200
    email_data = resp.json()
    assert email_data["risk_score"] > 25
    print(f"[PASS] Email Scanner Test Passed (Score: {email_data['risk_score']}, Classification: {email_data['risk_level']})")

    # 7. Test QR Scanner — Valid QR with Phishing URL
    qr_url = "http://192.168.1.1/login-verify.xyz"
    qr_bytes = make_qr_png_bytes(qr_url)
    files = {"file": ("test_qr.png", qr_bytes, "image/png")}
    resp = client.post("/api/v1/scan/qr", files=files)
    assert resp.status_code == 200
    qr_data = resp.json()
    assert qr_data["input_type"] == "qr"
    assert qr_data["risk_score"] > 65
    print(f"[PASS] QR Code End-to-End Phishing Test Passed (Decoded: {qr_data['normalized_input']}, Score: {qr_data['risk_score']})")

    # 8. Test QR Scanner — UPI Payment String QR Code
    upi_qr_text = "upi://pay?pa=scammer@upi&pn=RefundAgent&am=5000"
    upi_qr_bytes = make_qr_png_bytes(upi_qr_text)
    files_upi = {"file": ("upi_qr.png", upi_qr_bytes, "image/png")}
    resp = client.post("/api/v1/scan/qr", files=files_upi)
    assert resp.status_code == 200
    upi_data = resp.json()
    assert any(ind["code"] == "QR_UPI_PAYMENT_REQUEST" for ind in upi_data["detected_indicators"])
    assert upi_data["risk_score"] > 25
    assert upi_data["risk_level"] == "SUSPICIOUS"
    print(f"[PASS] QR Code UPI Payment Request Test Passed (Score: {upi_data['risk_score']}, Classification: {upi_data['risk_level']})")

    # 9. Test QR Scanner — Invalid Image Error Handling
    blank_img = Image.new("RGB", (100, 100), color=(255, 255, 255))
    blank_buf = io.BytesIO()
    blank_img.save(blank_buf, format="PNG")
    files_invalid = {"file": ("blank.png", blank_buf.getvalue(), "image/png")}
    resp = client.post("/api/v1/scan/qr", files=files_invalid)
    assert resp.status_code == 422
    assert "Unable to decode this QR code" in resp.json()["detail"]
    print("[PASS] Invalid QR Image Error Handling Passed (Returned 422 with clear error message)")

    # 10. Verify Removed Endpoints return 404
    assert client.get("/api/v1/intelligence/history").status_code == 404
    assert client.get("/api/v1/scenarios").status_code == 404
    assert client.post("/api/v1/reports", json={}).status_code == 404
    assert client.get("/api/v1/admin/stats").status_code == 404
    print("[PASS] Removed Endpoints Verification Passed (All returned 404 Not Found)")

    print("\nALL CYBERSHIELD AI VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_cybershield_suite()

