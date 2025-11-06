"""
ML Model Loader and Predictor
"""

import pickle
import os
from logger import log

class ModelPredictor:
    def __init__(self):
        try:
            from config import MODEL_PATH, VECTORIZER_PATH
            self.model_path = MODEL_PATH
            self.vectorizer_path = VECTORIZER_PATH
        except ImportError:
            try:
                from config import MODEL_PATH, VECT_PATH
                self.model_path = MODEL_PATH
                self.vectorizer_path = VECT_PATH
            except ImportError:
                self.model_path = "model/model.pkl"
                self.vectorizer_path = "model/vectorizer.pkl"
        
        self.model = None
        self.vectorizer = None
        self.load_models()
    
    def load_models(self):
        """Load ML model and vectorizer"""
        try:
            # Load model
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                log("Model loaded successfully")
            else:
                log(f"Model file not found: {self.model_path}")
                return False
            
            # Load vectorizer
            if os.path.exists(self.vectorizer_path):
                with open(self.vectorizer_path, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                log("Vectorizer loaded successfully")
            else:
                log(f"Vectorizer file not found: {self.vectorizer_path}")
                return False
            
            print("Models loaded successfully")
            return True
            
        except Exception as e:
            log(f"Error loading models: {e}")
            return False
    
    def safe_hostname(self, hostname):
        """Clean and prepare hostname for prediction"""
        if not hostname:
            return ""
        
        # Remove common prefixes
        cleaned = hostname.lower().strip()
        if cleaned.startswith('www.'):
            cleaned = cleaned[4:]
        
        return cleaned
    
    def predict_hostname(self, hostname):
        """Predict if hostname is harmful"""
        try:
            if not self.model or not self.vectorizer:
                log("Models not loaded")
                return 0  # Safe default
            
            # Vectorize input
            X = self.vectorizer.transform([hostname])
            
            # Make prediction
            prediction = self.model.predict(X)[0]
            return int(prediction)
            
        except Exception as e:
            log(f"Prediction error for {hostname}: {e}")
            return 0  # Safe default
    
    def predict_proba(self, hostname):
        """Get prediction probabilities if available"""
        try:
            if not self.model or not self.vectorizer:
                return [[0.5, 0.5]]  # Neutral default
            
            if hasattr(self.model, 'predict_proba'):
                X = self.vectorizer.transform([hostname])
                return self.model.predict_proba(X)
            else:
                # Fallback for models without probability
                pred = self.predict_hostname(hostname)
                if pred == 1:
                    return [[0.2, 0.8]]  # Harmful
                else:
                    return [[0.8, 0.2]]  # Safe
                    
        except Exception as e:
            log(f"Probability prediction error: {e}")
            return [[0.5, 0.5]]
