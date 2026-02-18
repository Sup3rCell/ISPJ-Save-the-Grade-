"""
Continuous Verification module
Provides: verify_document(document_id, mode='initial'|'manual'|'periodic')
Runs in app context and updates Document records and DocVersion snapshots.
"""
from datetime import datetime, timedelta
import hashlib
import os
import json

from models import db, Document, DocVersion, SecurityAlert
from modules.honeytoken_system import HoneytokenSystem
from modules.risk_engine import calculate_advanced_risk_score
from flask import current_app


def _compute_file_hash(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _create_alert(alert_type, severity, title, description, user_id=None, document_id=None, alert_data=None):
    try:
        alert = SecurityAlert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            user_id=user_id,
            document_id=document_id,
            alert_data=json.dumps(alert_data) if alert_data else None,
            status='new'
        )
        db.session.add(alert)
        db.session.commit()
        return alert
    except Exception as e:
        db.session.rollback()
        print(f"Failed to create security alert: {e}")
        return None


def verify_document(document_id, mode='initial'):
    # Lazy import of the Flask app to avoid circular imports when module is imported
    try:
        flask_app = current_app._get_current_object()
    except RuntimeError:
        from app import app as flask_app

    with flask_app.app_context():
        try:
            document = Document.query.get(document_id)
            if not document:
                print(f"verify_document: document {document_id} not found")
                return {'status': 'not_found'}

            file_hash = _compute_file_hash(document.filepath)
            file_size = None
            try:
                file_size = os.path.getsize(document.filepath)
            except Exception:
                pass

            notes = []

            # Honeytoken scan (try text scan, ignore binary failures)
            try:
                with open(document.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                tokens = HoneytokenSystem('honeytokens.json').detect_token(content)
                if tokens:
                    token_ids = [t['token_id'] for t in tokens]
                    notes.append(f"honeytokens:{token_ids}")
                    # create alert
                    _create_alert(
                        alert_type='honeytoken_detected',
                        severity='high',
                        title='Honeytoken detected during verification',
                        description=f'Honeytoken(s) found during verification for document {document.id}',
                        user_id=document.owner_id,
                        document_id=document.id,
                        alert_data={'tokens': token_ids}
                    )
                    # If honeytokens are present, fail verification immediately
                    document.verification_status = 'failed'
                    notes.append('failed_due_to_honeytoken')
            except Exception:
                # binary file or read error
                pass

            # Risk evaluation snapshot
            risk_score, risk_factors = calculate_advanced_risk_score(
                user=document.owner,
                action='verify',
                document=document
            )

            # Simple policy: if high risk -> fail verification
            if risk_score is not None and risk_score >= 90:
                document.verification_status = 'failed'
                notes.append('high_risk')
            else:
                document.verification_status = 'verified'

            document.last_verified_at = datetime.utcnow()
            document.verification_notes = ';'.join(notes) if notes else None
            document.verification_method = mode
            document.verification_attempts = (document.verification_attempts or 0) + 1

            # next verification scheduling based on classification
            if document.classification and document.classification.lower() in ('secret', 'confidential'):
                document.next_verification_at = datetime.utcnow() + timedelta(days=7)
            else:
                document.next_verification_at = datetime.utcnow() + timedelta(days=30)

            # Create a DocVersion snapshot
            try:
                latest_version = document.versions.order_by(DocVersion.version_number.desc()).first()
                next_version_number = 1 if not latest_version else latest_version.version_number + 1
                version = DocVersion(
                    document_id=document.id,
                    version_number=next_version_number,
                    storage_path=document.filepath,
                    file_hash=file_hash,
                    file_size=file_size,
                    encryption_key=document.encryption_key,
                    encryption_iv=document.encryption_iv,
                    created_by=document.owner_id,
                    risk_score_snapshot=risk_score,
                    notes=document.verification_notes
                )
                db.session.add(version)
            except Exception as e:
                print(f"Failed to create DocVersion snapshot: {e}")

            db.session.commit()

            print(f"Verification ({mode}) completed for document {document.id}: status={document.verification_status}")
            return {'status': document.verification_status, 'notes': document.verification_notes}

        except Exception as e:
            db.session.rollback()
            print(f"Error verifying document {document_id}: {e}")
            return {'status': 'error', 'error': str(e)}
