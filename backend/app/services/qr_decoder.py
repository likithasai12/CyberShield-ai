import io
import cv2
import numpy as np
from PIL import Image
from typing import Optional, Tuple

class QRDecoder:
    """
    Decodes uploaded QR code images into raw text/URL without navigating to or executing the destination.
    Uses multi-pass OpenCV QRCodeDetector preprocessing pipelines.
    """

    @staticmethod
    def _load_image_bgr(image_bytes: bytes) -> Optional[np.ndarray]:
        """
        Safely loads image bytes, compositing RGBA/LA/WebP transparency onto a solid white background.
        Returns BGR numpy array for OpenCV.
        """
        try:
            pil_img = Image.open(io.BytesIO(image_bytes))
            if pil_img.mode in ("RGBA", "LA") or (pil_img.mode == "P" and "transparency" in pil_img.info):
                pil_img = pil_img.convert("RGBA")
                bg = Image.new("RGBA", pil_img.size, (255, 255, 255, 255))
                alpha_composite = Image.alpha_composite(bg, pil_img)
                pil_img = alpha_composite.convert("RGB")
            else:
                pil_img = pil_img.convert("RGB")

            img_np = np.array(pil_img)
            return cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
        except Exception:
            # Fallback to direct OpenCV imdecode
            try:
                nparr = np.frombuffer(image_bytes, np.uint8)
                return cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            except Exception:
                return None

    @staticmethod
    def decode_image_bytes(image_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
        """
        Takes raw image bytes, decodes the QR code payload using multi-stage preprocessing,
        and returns (decoded_text, error_message).
        """
        try:
            img = QRDecoder._load_image_bgr(image_bytes)
            if img is None:
                return None, "Unable to decode this QR code. Please upload a clearer image."

            detector = cv2.QRCodeDetector()

            def try_decode(image_to_test: np.ndarray) -> Optional[str]:
                if image_to_test is None or image_to_test.size == 0:
                    return None
                # 1. Standard single decode
                data, bbox, _ = detector.detectAndDecode(image_to_test)
                if data and data.strip():
                    return data.strip()
                # 2. Multi-code decode fallback
                try:
                    retval, decoded_info, _, _ = detector.detectAndDecodeMulti(image_to_test)
                    if retval and decoded_info:
                        for text in decoded_info:
                            if text and text.strip():
                                return text.strip()
                except Exception:
                    pass
                return None

            # Attempt 1: Direct BGR Image
            res = try_decode(img)
            if res:
                return res, None

            # Attempt 2: White Border Padding (Fixes cropped QR codes missing quiet zones)
            h, w = img.shape[:2]
            pad_h, pad_w = max(30, int(h * 0.1)), max(30, int(w * 0.1))
            padded_img = cv2.copyMakeBorder(img, pad_h, pad_h, pad_w, pad_w, cv2.BORDER_CONSTANT, value=[255, 255, 255])
            res = try_decode(padded_img)
            if res:
                return res, None

            # Attempt 3: Scaled Variations (Upscale low-res, downscale large 4K screenshots)
            scales = []
            max_dim = max(h, w)
            min_dim = min(h, w)
            if max_dim > 2000:
                scales.extend([0.5, 0.33])
            if min_dim < 300:
                scales.extend([2.0, 3.0])
            if not scales:
                scales = [1.5, 0.75]

            for s in scales:
                scaled = cv2.resize(img, (0, 0), fx=s, fy=s, interpolation=cv2.INTER_CUBIC if s > 1.0 else cv2.INTER_AREA)
                res = try_decode(scaled)
                if res:
                    return res, None
                padded_scaled = cv2.copyMakeBorder(scaled, 30, 30, 30, 30, cv2.BORDER_CONSTANT, value=[255, 255, 255])
                res = try_decode(padded_scaled)
                if res:
                    return res, None

            # Attempt 4: Grayscale + CLAHE Contrast Enhancement
            gray = cv2.cvtColor(padded_img, cv2.COLOR_BGR2GRAY)
            res = try_decode(gray)
            if res:
                return res, None

            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced_gray = clahe.apply(gray)
            res = try_decode(enhanced_gray)
            if res:
                return res, None

            # Attempt 5: Thresholding Variations (Otsu, Inverted Otsu, Adaptive)
            _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            res = try_decode(otsu)
            if res:
                return res, None

            _, inv_otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
            res = try_decode(inv_otsu)
            if res:
                return res, None

            adapt_thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
            res = try_decode(adapt_thresh)
            if res:
                return res, None

            # Attempt 6: Sharpening Filter (Sharpen JPEG compression artifacts)
            kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
            sharpened = cv2.filter2D(gray, -1, kernel)
            res = try_decode(sharpened)
            if res:
                return res, None

            return None, "Unable to decode this QR code. Please upload a clearer image."

        except Exception as e:
            return None, "Unable to decode this QR code. Please upload a clearer image."

qr_decoder = QRDecoder()

