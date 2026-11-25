"""Acceptance tests for the injection-audit commercial checkout rail.

The landing page must offer a real, inbound Stripe checkout and the API-verified
record must pin a live price. No secret values are read here - only the record.
"""
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "index.html"
CHECKOUT = ROOT / "checkout.json"

URL_RE = re.compile(r"https://buy[.]stripe[.]com/[A-Za-z0-9]+")


def test_landing_has_stripe_checkout_link():
    urls = URL_RE.findall(INDEX.read_text(encoding="utf-8"))
    assert urls, "landing page has no Stripe checkout link"


def test_checkout_record_is_live_and_priced():
    assert CHECKOUT.exists(), "no API-verified checkout.json"
    rec = json.loads(CHECKOUT.read_text(encoding="utf-8"))
    assert rec["mode"] == "live", "checkout must be live mode"
    assert rec["currency"] == "eur"
    assert rec["amount_eur"] > 0
    assert rec["url"].startswith("https://buy.stripe.com/")
    assert rec["stripe_price_id"].startswith("price_")
    assert "GET /v1/payment_links" in rec["evidence"]


def test_landing_link_matches_record():
    urls = set(URL_RE.findall(INDEX.read_text(encoding="utf-8")))
    rec = json.loads(CHECKOUT.read_text(encoding="utf-8"))
    assert rec["url"] in urls, "landing link does not match verified checkout URL"
