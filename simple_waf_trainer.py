import csv
import os
import logging
from datetime import datetime
import pickle

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SimpleWAFTrainer:
    """Simple WAF ML Trainer using basic Python"""
    
    def __init__(self, data_dir='Data_Collection'):
        self.data_dir = data_dir
        self.model = None
        self.feature_columns = [
            'single_q', 'double_q', 'dashes', 'braces', 'spaces', 
            'percentages', 'semicolons', 'angle_brackets', 'special_chars',
            'path_length', 'body_length', 'badwords_count'
        ]
        
    def load_csv_data(self, filepath):
        """Load data from CSV file"""
        data = []
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    data.append(row)
            logger.info(f"Loaded {len(data)} records from {filepath}")
            return data
        except Exception as e:
            logger.error(f"Error loading {filepath}: {e}")
            return []
    
    def load_all_data(self):
        """Load and combine data from CSV files"""
        try:
            logger.info("Loading data files...")
            
            all_data = []
            
            # Try to load each CSV file
            csv_files = ['All_data.csv', 'Bad_req.csv', 'Good_req.csv']
            
            for filename in csv_files:
                filepath = os.path.join(self.data_dir, filename)
                if os.path.exists(filepath):
                    data = self.load_csv_data(filepath)
                    all_data.extend(data)
                else:
                    logger.warning(f"File not found: {filepath}")
            
            if not all_data:
                raise FileNotFoundError("No CSV files found in Data_Collection directory")
            
            logger.info(f"Total combined dataset: {len(all_data)} records")
            return all_data
            
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            raise
    
    def preprocess_data(self, data):
        """Preprocess the data"""
        try:
            logger.info("Preprocessing data...")
            
            X = []
            y = []
            
            for row in data:
                # Extract features
                features = []
                for col in self.feature_columns:
                    try:
                        value = float(row.get(col, 0))
                        features.append(value)
                    except (ValueError, TypeError):
                        features.append(0.0)
                
                # Extract target (0=good, 1=bad)
                class_label = row.get('class', '').lower()
                target = 1 if class_label == 'bad' else 0
                
                X.append(features)
                y.append(target)
            
            logger.info(f"Processed {len(X)} samples")
            logger.info(f"Good requests: {y.count(0)}, Bad requests: {y.count(1)}")
            
            return X, y
            
        except Exception as e:
            logger.error(f"Error preprocessing data: {e}")
            raise
    
    def train_simple_model(self, X_train, y_train):
        """Train a simple rule-based model"""
        try:
            logger.info("Training simple rule-based model...")
            
            # Calculate feature statistics for bad requests
            bad_features = []
            good_features = []
            
            for features, label in zip(X_train, y_train):
                if label == 1:  # bad
                    bad_features.append(features)
                else:  # good
                    good_features.append(features)
            
            # Calculate averages for each feature
            bad_avg = [sum(col) / len(col) for col in zip(*bad_features)] if bad_features else [0] * len(self.feature_columns)
            good_avg = [sum(col) / len(col) for col in zip(*good_features)] if good_features else [0] * len(self.feature_columns)
            
            # Create simple threshold model
            thresholds = []
            for i in range(len(self.feature_columns)):
                # Use midpoint between good and bad averages as threshold
                threshold = (good_avg[i] + bad_avg[i]) / 2
                thresholds.append(threshold)
            
            self.model = {
                'type': 'threshold_based',
                'thresholds': thresholds,
                'feature_columns': self.feature_columns,
                'bad_avg': bad_avg,
                'good_avg': good_avg
            }
            
            logger.info("Simple threshold model trained successfully")
            return self.model
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            raise
    
    def predict_sample(self, features):
        """Predict single sample using threshold model"""
        if not self.model:
            raise ValueError("Model not trained")
        
        thresholds = self.model['thresholds']
        
        # Count how many features exceed thresholds
        score = 0
        for i, (feature, threshold) in enumerate(zip(features, thresholds)):
            if feature > threshold:
                score += 1
        
        # If more than half the features exceed thresholds, classify as bad
        probability = score / len(features)
        return probability
    
    def evaluate_model(self, X_test, y_test):
        """Evaluate the model"""
        try:
            logger.info("Evaluating model...")
            
            correct = 0
            predictions = []
            
            for features, true_label in zip(X_test, y_test):
                probability = self.predict_sample(features)
                prediction = 1 if probability > 0.5 else 0
                predictions.append(prediction)
                
                if prediction == true_label:
                    correct += 1
            
            accuracy = correct / len(y_test)
            logger.info(f"Test accuracy: {accuracy:.4f}")
            
            # Calculate confusion matrix
            tp = fp = tn = fn = 0
            for pred, true in zip(predictions, y_test):
                if pred == 1 and true == 1:
                    tp += 1
                elif pred == 1 and true == 0:
                    fp += 1
                elif pred == 0 and true == 0:
                    tn += 1
                elif pred == 0 and true == 1:
                    fn += 1
            
            logger.info(f"Confusion Matrix:")
            logger.info(f"True Positive: {tp}, False Positive: {fp}")
            logger.info(f"True Negative: {tn}, False Negative: {fn}")
            
            return {
                'accuracy': accuracy,
                'confusion_matrix': [[tn, fp], [fn, tp]],
                'predictions': predictions
            }
            
        except Exception as e:
            logger.error(f"Error evaluating model: {e}")
            raise
    
    def save_model(self, model_path='models/waf_model.pkl'):
        """Save the trained model"""
        try:
            # Create models directory if it doesn't exist
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            
            # Save model
            with open(model_path, 'wb') as f:
                pickle.dump(self.model, f)
            
            logger.info(f"Model saved to {model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def split_data(self, X, y, test_size=0.2):
        """Simple train-test split"""
        try:
            import random
            
            # Combine features and labels
            combined = list(zip(X, y))
            random.shuffle(combined)
            
            split_idx = int(len(combined) * (1 - test_size))
            train_data = combined[:split_idx]
            test_data = combined[split_idx:]
            
            X_train = [item[0] for item in train_data]
            y_train = [item[1] for item in train_data]
            X_test = [item[0] for item in test_data]
            y_test = [item[1] for item in test_data]
            
            logger.info(f"Training set: {len(X_train)} samples")
            logger.info(f"Test set: {len(X_test)} samples")
            
            return X_train, X_test, y_train, y_test
            
        except Exception as e:
            logger.error(f"Error splitting data: {e}")
            raise
    
    def train_complete_pipeline(self):
        """Complete training pipeline"""
        try:
            logger.info("Starting simple WAF model training...")
            
            # Load data
            data = self.load_all_data()
            
            # Preprocess data
            X, y = self.preprocess_data(data)
            
            # Split data
            X_train, X_test, y_train, y_test = self.split_data(X, y)
            
            # Train model
            model = self.train_simple_model(X_train, y_train)
            
            # Evaluate model
            results = self.evaluate_model(X_test, y_test)
            
            # Save model
            if self.save_model():
                logger.info("Model training completed successfully!")
                return {
                    'model_type': model['type'],
                    'accuracy': results['accuracy'],
                    'feature_columns': model['feature_columns'],
                    'training_time': datetime.now().isoformat()
                }
            else:
                raise Exception("Failed to save model")
                
        except Exception as e:
            logger.error(f"Training pipeline failed: {e}")
            raise

def main():
    """Main function"""
    try:
        trainer = SimpleWAFTrainer()
        results = trainer.train_complete_pipeline()
        
        print("\n" + "="*50)
        print("SIMPLE WAF MODEL TRAINING COMPLETED")
        print("="*50)
        print(f"Model Type: {results['model_type']}")
        print(f"Accuracy: {results['accuracy']:.4f}")
        print(f"Training Time: {results['training_time']}")
        print(f"Features: {', '.join(results['feature_columns'])}")
        print("\nModel saved to: models/waf_model.pkl")
        print("="*50)
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        print(f"Error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
