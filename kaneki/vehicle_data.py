"""RDW vehicle record normalization."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def analyze_vehicle(car: dict[str, Any]) -> dict[str, str]:
    report = {
        "License Plate": car.get("kenteken", "Unknown"),
        "Vehicle": f"{car.get('merk', 'Unknown')} {car.get('handelsbenaming', 'Unknown')}",
        "Vehicle Type": car.get("voertuigsoort", "Unknown"),
        "Body Type": car.get("inrichting", "Unknown"),
        "Primary Color": car.get("eerste_kleur", "Unknown"),
        "Secondary Color": car.get("tweede_kleur", "Unknown"),
        "Fuel Type": car.get("brandstof_omschrijving", "Unknown"),
        "Engine": f"{car.get('aantal_cilinders', 'Unknown')} cyl, {car.get('cilinderinhoud', 'Unknown')}cc",
        "Weight": f"{car.get('massa_ledig_voertuig', 'Unknown')} kg empty / {car.get('toegestane_maximum_massa_voertuig', 'Unknown')} kg max",
        "Seats": str(car.get("aantal_zitplaatsen", "Unknown")),
        "Doors": str(car.get("aantal_deuren", "Unknown")),
        "First Registration": car.get("datum_eerste_toelating", "Unknown"),
        "Current Registration": car.get("datum_tenaamstelling", "Unknown"),
        "APK Expiry": car.get("vervaldatum_apk", "Unknown"),
        "Catalog Price": f"€{car.get('catalogusprijs', 'Unknown')}",
        "BPM Tax": f"€{car.get('bruto_bpm', 'Unknown')}",
        "WAM Insured": car.get("wam_verzekerd", "Unknown"),
        "Export Indicator": car.get("export_indicator", "Unknown"),
        "Taxi Indicator": car.get("taxi_indicator", "Unknown"),
        "Last Mileage Year": str(car.get("jaar_laatste_registratie_tellerstand", "Unknown")),
    }

    risks = []
    if car.get("wam_verzekerd") == "Nee":
        risks.append("Not WAM insured")
    if car.get("export_indicator") == "Ja":
        risks.append("Marked for export")
    if car.get("taxi_indicator") == "Ja":
        risks.append("Commercial taxi use")

    try:
        first_registration = car.get("datum_eerste_toelating", "")
        if first_registration and first_registration != "Unknown":
            age = datetime.now().year - int(str(first_registration)[:4])
            report["Vehicle Age"] = f"{age} years"
            if age > 15:
                risks.append("Very old vehicle (>15 years)")
            elif age > 10:
                risks.append("Old vehicle (>10 years)")
        else:
            report["Vehicle Age"] = "Unknown"
    except Exception:
        report["Vehicle Age"] = "Unknown"

    report["Risk Level"] = "LOW" if not risks else ("MEDIUM" if len(risks) == 1 else "HIGH")
    report["Risk Factors"] = ", ".join(risks) if risks else "None identified"
    report["Data Source"] = "RDW Open Data API (opendata.rdw.nl)"
    return report
