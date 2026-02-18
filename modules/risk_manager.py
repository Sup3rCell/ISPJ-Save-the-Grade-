import json
from datetime import datetime, timedelta
from flask import g
from models import db, RiskState, User, AccessLog, Document

class RiskManager:
    """
    Centralized module to manage persistent risk scores for users.
    Now includes comprehensive Zero-Trust Risk Scoring.
    """
    
    # Configuration for Risk Weights
    WEIGHTS = {
        'identity': 0.35,
        'location': 0.35,
        'sensitivity': 0.25,
        'action': 0.05
    }

    # ============================================
    # NEW: Request-Scoped Aggregation (The "Easy" Way)
    # ============================================

    @classmethod
    def submit_risk_component(cls, context, score, factors):
        """
        Registers a risk component for the current request context.
        Call this from within your detection functions (e.g. risk_engine).
        
        Args:
            context (str): The component name (e.g., 'location', 'identity').
            score (int): The calculated score (0-100).
            factors (list): List of risk factor strings.
        """
        if 'risk_components' not in g:
            g.risk_components = {}
            
        g.risk_components[context] = (score, factors)
        # Return score for convenience/back-compatibility
        return score

    @classmethod
    def finalize_risk_assessment(cls, user):
        """
        Calculates the final weighted score based on all components submitted 
        during this request via `submit_risk_component`.
        """
        components = getattr(g, 'risk_components', {})
        
        # Reuse the aggregation logic
        return cls.aggregate_weighted_risk(user, **components)


    @staticmethod
    def get_current_risk(user_id):
        """
        Get the current risk score and factors for a user.
        """
        risk_state = RiskState.query.filter_by(user_id=user_id).first()
        
        if not risk_state:
            # Initialize if not exists
            risk_state = RiskState(user_id=user_id, current_score=0, risk_factors='[]')
            db.session.add(risk_state)
            try:
                db.session.commit()
            except:
                db.session.rollback()
            
        factors = []
        try:
            factors = json.loads(risk_state.risk_factors)
        except:
            factors = []
            
        return {
            "score": risk_state.current_score,
            "factors": factors
        }

    @staticmethod
    def update_risk(user_id, amount, reason):
        """
        Add (or subtract) persistent risk score.
        """
        # Get or create state
        risk_state = RiskState.query.filter_by(user_id=user_id).first()
        if not risk_state:
            risk_state = RiskState(user_id=user_id, current_score=0, risk_factors='[]')
            db.session.add(risk_state)
        
        # Update score
        new_score = risk_state.current_score + amount
        # Clamp between 0 and 100
        new_score = max(0, min(100, new_score))
        
        risk_state.current_score = new_score
        risk_state.last_updated = datetime.utcnow()
        
        # Update factors
        factors = []
        try:
            factors = json.loads(risk_state.risk_factors)
        except:
            factors = []
            
        # Add new reason if positive risk update
        if amount > 0:
            timestamp = datetime.utcnow().strftime("%H:%M:%S")
            factors.append(f"{reason} (+{amount}) at {timestamp}")
            
            # Keep only last 10 factors
            if len(factors) > 10:
                factors = factors[-10:]
        
        if amount < 0:
             factors.append(f"{reason} ({amount}) at {datetime.utcnow().strftime('%H:%M:%S')}")

        risk_state.risk_factors = json.dumps(factors)
        
        # Save
        try:
            db.session.commit()
            
            # Audit log
            log = AccessLog(
                user_id=user_id,
                action='RISK_UPDATE',
                outcome='success',
                risk_score=new_score,
                risk_factors=json.dumps([reason]),
                action_details=json.dumps({'amount': amount, 'reason': reason})
            )
            db.session.add(log)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating risk: {e}")
            
        return new_score

    @staticmethod
    def reset_risk(user_id, reason="Manual Reset"):
        """
        Resets persistent risk score to 0.
        """
        risk_state = RiskState.query.filter_by(user_id=user_id).first()
        if risk_state:
            risk_state.current_score = 0
            risk_state.risk_factors = '[]'
            risk_state.last_updated = datetime.utcnow()
            
            log = AccessLog(
                user_id=user_id,
                action='RISK_RESET',
                outcome='success',
                risk_score=0,
                action_details=json.dumps({'reason': reason})
            )
            db.session.add(log)
            db.session.commit()
            
        return 0

    # ============================================
    # NEW: Zero-Trust Weighted Aggregation
    # ============================================

    @classmethod
    def aggregate_weighted_risk(cls, user, **components):
        """
        Aggregates risk scores from ANY provided components using configured weights.
        
        Usage:
            RiskManager.aggregate_weighted_risk(
                user, 
                identity=(score, ['factor1']), 
                location=(score, ['factor2']),
                custom_module=(score, ['factor3'])
            )
            
        Args:
            user (User): The user object.
            **components: Keyword arguments where key is component name (must exist in WEIGHTS)
                          and value is tuple (score, factors_list).
            
        Returns:
            tuple: (final_score, breakdown_dict)
        """
        if not user:
            return 0, {}

        weighted_score = 0
        breakdown_components = {}
        
        # 1. Aggregate and Weight Components
        for name, data in components.items():
            if not data or not isinstance(data, (tuple, list)) or len(data) != 2:
                continue
                
            score = data[0]
            factors = data[1]
            
            # Get weight (default to 0 if not configured, to avoid errors on new modules)
            weight = cls.WEIGHTS.get(name, 0.0)
            
            # Add to total weighted score
            weighted_score += (score * weight)
            
            # Store for breakdown
            breakdown_components[name] = {
                'score': score, 
                'factors': factors,
                'weight': weight
            }
            
        weighted_score = round(weighted_score)
        
        # 2. Get Persistent Risk (History of bad behavior)
        persistent_data = cls.get_current_risk(user.id)
        persistent_score = persistent_data['score']
        persistent_factors = persistent_data['factors']
        
        # Add persistent data to breakdown for completeness
        breakdown_components['persistent'] = {
            'score': persistent_score, 
            'factors': persistent_factors,
            'weight': 1.0 # Persistent risk is added flatly (weight 1.0)
        }
        
        # 3. Final Calculation
        # Combine weighted context risk with persistent risk
        final_score = weighted_score + persistent_score
        final_score = min(100, max(0, final_score))
        
        breakdown = {
            'final_score': final_score,
            'weighted_score': weighted_score,
            'persistent_score': persistent_score,
            'components': breakdown_components
        }
        
        # Optionally: We could auto-update the DB with this new "Session Risk" snapshot here
        # But for now we just return it for the caller to decide (e.g. log_attempt)
        
        return final_score, breakdown

