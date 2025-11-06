"""
Confidence-based ML Predictions
"""

import numpy as np
from model_loader import ModelPredictor
from logger import log

class ConfidenceAnalyzer:
    def __init__(self):
        self.predictor = ModelPredictor()
    
    def predict_with_confidence(self, hostname):
        """Get prediction with confidence score"""
        try:
            if not self.predictor.model or not self.predictor.vectorizer:
                return 0, 0.5  # Safe default
            
            h = self.predictor.safe_hostname(hostname)
            
            # Get probability scores if available
            if hasattr(self.predictor.model, 'predict_proba'):
                probabilities = self.predictor.model.predict_proba(
                    self.predictor.vectorizer.transform([h])
                )[0]
                
                confidence = np.max(probabilities)
                prediction = np.argmax(probabilities)
                
            else:
                # Fallback for models without probability support
                prediction = self.predictor.predict_hostname(h)
                confidence = 0.6 if prediction == 0 else 0.8
            
            return prediction, confidence
            
        except Exception as e:
            log(f"Confidence prediction error for {hostname}: {e}")
            return 0, 0.5  # Safe default
