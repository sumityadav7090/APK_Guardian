import os
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load the dataset
def load_dataset(dataset_path):
    with open(dataset_path, 'rb') as f:
        dataset = pickle.load(f)
    return dataset

# Train a model
def train_model(dataset):
    X = dataset['features']
    y = dataset['labels']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    return model

# Save the model
def save_model(model, model_path):
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)

# Load the model
def load_model(model_path):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    return model

# Use the model to make predictions
def make_predictions(model, features):
    predictions = model.predict(features)
    return predictions

def load_or_train_model(dataset_path="dataset.pkl", model_path="model.pkl"):
    if os.path.exists(model_path):
        print("✅ Loading existing model...")
        return load_model(model_path), None
    else:
        print("⚡ Training new model...")
        if os.path.exists(dataset_path):
            dataset = load_dataset(dataset_path)
        else:
            # 🔹 fallback dummy dataset
            print("⚠️ No dataset found, using dummy data...")
            dataset = {
                "features": [[0, 1], [1, 0], [1, 1], [0, 0]],
                "labels":   [1, 0, 1, 0]
            }
        model = train_model(dataset)
        save_model(model, model_path)
        return model, list(range(len(dataset["features"][0])))

