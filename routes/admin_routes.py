# routes/admin_routes.py
from flask import Blueprint, render_template
from datetime import datetime, timedelta
from models import AccessLog, User, Document, db   # adjust imports to your structure

admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
    template_folder="../templates/admin"
)

@admin_bp.route("/")
def dashboard_root():
    # TODO: compute real KPIs later
    kpis = {
        "active_sessions": 0,
        "high_risk_today": 0,
        "impossible_travel_24h": AccessLog.query.filter(
            AccessLog.impossible_travel_flag.is_(True),
            AccessLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).count(),
        "honeytokens_week": 0,
    }
    return render_template(
        "admin/dashboard.html",
        kpis=kpis,
        recent_risky_events=[],
        recent_honeytokens=[]
    )

@admin_bp.route("/dashboard")
def dashboard():
    # reuse same logic as root
    return dashboard_root()

@admin_bp.route("/logs")
def logs():
    # latest 100 access logs
    rows = (AccessLog.query
            .order_by(AccessLog.timestamp.desc())
            .limit(100)
            .all())

    access_logs = []
    for r in rows:
        user = User.query.get(r.user_id) if r.user_id else None
        doc = Document.query.get(r.document_id) if r.document_id else None

        access_logs.append({
            "time": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "user": user.email if user else "Unknown",
            "action": r.action,
            "document": doc.title if doc else None,
            "ip": r.ip_address,
            # assume location is "City, Country" or just "Country"
            "country": (r.location or "").split(",")[-1].strip() if r.location else "-",
            "risk_score": r.risk_score or 0,
            "risk_level": "High" if (r.risk_score or 0) >= 70 else
                          "Medium" if (r.risk_score or 0) >= 40 else "Low",
            "travel_speed_kmh": r.travel_speed_kmh,
            "impossible_travel_flag": bool(r.impossible_travel_flag),
            "result": r.outcome,
        })

    return render_template("admin/logs.html", access_logs=access_logs)

@admin_bp.route("/risk")
def risk_history():
    # TODO: integrate real risk-events table if you add one
    risk_events = []

    # impossible travel in last 7 days
    since = datetime.utcnow() - timedelta(days=7)
    rows = (AccessLog.query
            .filter(
                AccessLog.impossible_travel_flag.is_(True),
                AccessLog.timestamp >= since
            )
            .order_by(AccessLog.timestamp.desc())
            .limit(50)
            .all())

    impossible_events = []
    for r in rows:
        user = User.query.get(r.user_id) if r.user_id else None

        impossible_events.append({
            "time": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "user": user.email if user else "Unknown",
            "location": r.location or "-",
            # optional: store previous location in a separate field if you want to display it
            "prev_location": getattr(r, "prev_location", "-"),
            "travel_speed_kmh": r.travel_speed_kmh or 0,
        })

    impossible_count = len(impossible_events)

    return render_template(
        "admin/risk_history.html",
        risk_events=risk_events,
        impossible_events=impossible_events,
        impossible_count=impossible_count
    )

@admin_bp.route("/documents")
def documents():
    documents = []
    return render_template("admin/documents.html", documents=documents)

@admin_bp.route("/honeytokens")
def honeytokens():
    tokens = []
    return render_template("admin/honeytokens.html", tokens=tokens)
