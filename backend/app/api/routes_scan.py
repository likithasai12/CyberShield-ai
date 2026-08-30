import datetime
from fastapi import APIRouter, File, UploadFile, HTTPException, status
from app.schemas.scan_schema import (
    URLScanRequest, MessageScanRequest, EmailScanRequest, ScanResultResponse
)
from app.services.url_analyzer import url_analyzer
from app.services.message_analyzer import message_analyzer
from app.services.qr_decoder import qr_decoder
from app.services.ai_analyzer import ai_analyzer
from app.services.threat_intel import threat_intel_service
from app.services.supabase_service import supabase_service
from app.core.risk_engine import risk_engine
from app.core.explanation_engine import explanation_engine

router = APIRouter(prefix="/api/v1/scan", tags=["Scanner"])

@router.post("/url", response_model=ScanResultResponse)
async def scan_url(payload: URLScanRequest):
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL input cannot be empty.")

    normalized_url = url_analyzer.normalize_url(raw_url)
    content_hash = supabase_service.generate_hash(normalized_url)

    # 1. Lookup prior threat intelligence from Supabase (context signal)
    stored_intel = await supabase_service.get_threat_intelligence(content_hash)
    stored_found = bool(stored_intel)

    # 2. Run structural pattern analysis
    indicators = url_analyzer.analyze(normalized_url)

    # 3. Run external threat intelligence (if configured)
    external_indicators = await threat_intel_service.check_url_threats(normalized_url)
    indicators.extend(external_indicators)

    # 4. Compute composite risk score & classification
    risk_score, risk_level, threat_category = risk_engine.calculate_risk(indicators, stored_intel)

    # 5. Generate Evidence -> Explanation -> Recommendations
    exp_dict, recommendations = explanation_engine.generate_explanation(
        risk_score, risk_level, threat_category, indicators, input_type="URL"
    )

    # 6. Save scan event & update persistent threat memory in Supabase
    db_ok1 = await supabase_service.save_scan_event(
        content_hash=content_hash,
        input_type="url",
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        indicators=indicators,
        explanation=exp_dict,
        recommendations=recommendations
    )
    db_ok2 = await supabase_service.update_threat_intelligence(
        content_hash=content_hash,
        identifier=normalized_url[:100],
        content_type="url",
        threat_category=threat_category,
        risk_score=risk_score,
        indicators=indicators
    )

    db_status = "connected" if (db_ok1 or supabase_service.is_connected) else "storage_unavailable"

    return ScanResultResponse(
        content_hash=content_hash,
        input_type="url",
        normalized_input=normalized_url,
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        detected_indicators=indicators,
        explanation=exp_dict,
        recommendations=recommendations,
        stored_intel_found=stored_found,
        stored_intel_details={
            "scan_count": stored_intel.get("scan_count") if stored_intel else None,
            "last_seen_at": stored_intel.get("last_seen_at") if stored_intel else None
        } if stored_found else None,
        db_status=db_status,
        analyzed_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


@router.post("/message", response_model=ScanResultResponse)
async def scan_message(payload: MessageScanRequest):
    raw_message = payload.message.strip()
    if not raw_message:
        raise HTTPException(status_code=400, detail="Message content cannot be empty.")

    masked_message = message_analyzer.mask_sensitive_data(raw_message)
    content_hash = supabase_service.generate_hash(raw_message)

    # 1. Lookup prior threat memory
    stored_intel = await supabase_service.get_threat_intelligence(content_hash)
    stored_found = bool(stored_intel)

    # 2. Run NLP & Social Engineering Heuristics
    indicators, extracted_urls = message_analyzer.analyze(raw_message)

    # 3. Run optional AI context analysis
    ai_indicators = await ai_analyzer.analyze_context(raw_message, "message")
    indicators.extend(ai_indicators)

    # 4. Risk Engine
    risk_score, risk_level, threat_category = risk_engine.calculate_risk(indicators, stored_intel)

    # 5. Explanation Engine
    exp_dict, recommendations = explanation_engine.generate_explanation(
        risk_score, risk_level, threat_category, indicators, input_type="Message"
    )

    # 6. Save to Supabase
    db_ok1 = await supabase_service.save_scan_event(
        content_hash=content_hash,
        input_type="message",
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        indicators=indicators,
        explanation=exp_dict,
        recommendations=recommendations
    )
    db_ok2 = await supabase_service.update_threat_intelligence(
        content_hash=content_hash,
        identifier=masked_message[:80] + ("..." if len(masked_message) > 80 else ""),
        content_type="message",
        threat_category=threat_category,
        risk_score=risk_score,
        indicators=indicators
    )

    db_status = "connected" if (db_ok1 or supabase_service.is_connected) else "storage_unavailable"

    return ScanResultResponse(
        content_hash=content_hash,
        input_type="message",
        normalized_input=masked_message,
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        detected_indicators=indicators,
        explanation=exp_dict,
        recommendations=recommendations,
        stored_intel_found=stored_found,
        stored_intel_details={
            "scan_count": stored_intel.get("scan_count") if stored_intel else None,
            "last_seen_at": stored_intel.get("last_seen_at") if stored_intel else None
        } if stored_found else None,
        db_status=db_status,
        analyzed_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


@router.post("/email", response_model=ScanResultResponse)
async def scan_email(payload: EmailScanRequest):
    body = payload.body.strip()
    subject = (payload.subject or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Email body content cannot be empty.")

    full_email_str = f"Subject: {subject}\n{body}"
    masked_email = message_analyzer.mask_sensitive_data(full_email_str)
    content_hash = supabase_service.generate_hash(full_email_str)

    stored_intel = await supabase_service.get_threat_intelligence(content_hash)
    stored_found = bool(stored_intel)

    indicators, extracted_urls = message_analyzer.analyze(body, subject=subject)
    ai_indicators = await ai_analyzer.analyze_context(full_email_str, "email")
    indicators.extend(ai_indicators)

    risk_score, risk_level, threat_category = risk_engine.calculate_risk(indicators, stored_intel)

    exp_dict, recommendations = explanation_engine.generate_explanation(
        risk_score, risk_level, threat_category, indicators, input_type="Email"
    )

    db_ok1 = await supabase_service.save_scan_event(
        content_hash=content_hash,
        input_type="email",
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        indicators=indicators,
        explanation=exp_dict,
        recommendations=recommendations
    )
    db_ok2 = await supabase_service.update_threat_intelligence(
        content_hash=content_hash,
        identifier=f"Subject: {subject[:50]}" if subject else masked_email[:80],
        content_type="email",
        threat_category=threat_category,
        risk_score=risk_score,
        indicators=indicators
    )

    db_status = "connected" if (db_ok1 or supabase_service.is_connected) else "storage_unavailable"

    return ScanResultResponse(
        content_hash=content_hash,
        input_type="email",
        normalized_input=masked_email,
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        detected_indicators=indicators,
        explanation=exp_dict,
        recommendations=recommendations,
        stored_intel_found=stored_found,
        stored_intel_details={
            "scan_count": stored_intel.get("scan_count") if stored_intel else None,
            "last_seen_at": stored_intel.get("last_seen_at") if stored_intel else None
        } if stored_found else None,
        db_status=db_status,
        analyzed_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


@router.post("/qr", response_model=ScanResultResponse)
async def scan_qr(file: UploadFile = File(...)):
    filename = (file.filename or "").lower()
    is_img = (file.content_type and file.content_type.startswith("image/")) or any(filename.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tiff"])
    if not is_img:
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload an image file (PNG, JPG, WebP).")

    contents = await file.read()
    decoded_text, err = qr_decoder.decode_image_bytes(contents)

    if err or not decoded_text:
        raise HTTPException(status_code=422, detail=err or "Unable to read QR code from image.")

    content_hash = supabase_service.generate_hash(decoded_text)
    stored_intel = await supabase_service.get_threat_intelligence(content_hash)
    stored_found = bool(stored_intel)

    # Detect if decoded content is a URL vs message/payment text
    if decoded_text.startswith(("http://", "https://", "www.")) or "." in decoded_text.split("/")[0]:
        input_sub_type = "url"
        normalized_text = url_analyzer.normalize_url(decoded_text)
        indicators = url_analyzer.analyze(normalized_text)
        ext_inds = await threat_intel_service.check_url_threats(normalized_text)
        indicators.extend(ext_inds)
    else:
        input_sub_type = "message"
        normalized_text = message_analyzer.mask_sensitive_data(decoded_text)
        indicators, _ = message_analyzer.analyze(decoded_text)

    # Check for QR Payment Scam Specific Signal (e.g. UPI pay request)
    if "upi://" in decoded_text.lower() or "pay?" in decoded_text.lower() or "pn=" in decoded_text.lower():
        indicators.append({
            "code": "QR_UPI_PAYMENT_REQUEST",
            "label": "Direct UPI Payment String Decoded",
            "severity": "high",
            "description": "QR code initiates a UPI money request. Scanning a QR code is ONLY required to PAY money, NEVER to receive money.",
            "weight": 30
        })

    risk_score, risk_level, threat_category = risk_engine.calculate_risk(indicators, stored_intel)

    exp_dict, recommendations = explanation_engine.generate_explanation(
        risk_score, risk_level, threat_category, indicators, input_type="QR Code Destination"
    )

    db_ok1 = await supabase_service.save_scan_event(
        content_hash=content_hash,
        input_type="qr",
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        indicators=indicators,
        explanation=exp_dict,
        recommendations=recommendations
    )
    db_ok2 = await supabase_service.update_threat_intelligence(
        content_hash=content_hash,
        identifier=f"Decoded QR: {normalized_text[:70]}",
        content_type="qr",
        threat_category=threat_category,
        risk_score=risk_score,
        indicators=indicators
    )

    db_status = "connected" if (db_ok1 or supabase_service.is_connected) else "storage_unavailable"

    return ScanResultResponse(
        content_hash=content_hash,
        input_type="qr",
        normalized_input=normalized_text,
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        detected_indicators=indicators,
        explanation=exp_dict,
        recommendations=recommendations,
        stored_intel_found=stored_found,
        stored_intel_details={
            "scan_count": stored_intel.get("scan_count") if stored_intel else None,
            "last_seen_at": stored_intel.get("last_seen_at") if stored_intel else None
        } if stored_found else None,
        db_status=db_status,
        analyzed_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
