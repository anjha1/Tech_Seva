from flask import Flask, render_template, request
import joblib
import pandas as pd
from datetime import datetime
import numpy as np
import requests
import os

# Model files load karein. Agar files nahi mili to error dikhayega.
try:
    model = joblib.load('uber_fare_predictor.pkl')
    model_features = joblib.load('model_features.pkl')
except FileNotFoundError:
    print("Error: The model files 'uber_fare_predictor.pkl' or 'model_features.pkl' were not found.")
    print("Please make sure you have trained and saved the model correctly in the same directory.")
    exit()

app = Flask(__name__)

# Google Maps API key (set in environment variable)
GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY')
if not GOOGLE_MAPS_API_KEY:
    print("Error: GOOGLE_MAPS_API_KEY environment variable not set.")
    exit()

def get_distance_google_maps(pickup_lat, pickup_lon, dropoff_lat, dropoff_lon):
    """
    Get distance using Google Maps Distance Matrix API
    """
    try:
        url = f"https://maps.googleapis.com/maps/api/distancematrix/json?origins={pickup_lat},{pickup_lon}&destinations={dropoff_lat},{dropoff_lon}&key={GOOGLE_MAPS_API_KEY}&units=metric"
        response = requests.get(url)
        data = response.json()
        if data['status'] == 'OK' and data['rows'][0]['elements'][0]['status'] == 'OK':
            distance_m = data['rows'][0]['elements'][0]['distance']['value']
            distance_km = distance_m / 1000.0
            return distance_km
        else:
            print(f"Google Maps API error: {data['status']}")
            return None
    except Exception as e:
        print(f"Error calling Google Maps API: {e}")
        return None

def haversine_distance(lat1, lon1, lat2, lon2):
    """
    Calculate the great circle distance between two points on the earth (specified in decimal degrees)
    Fallback if Google Maps fails
    """
    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])

    # Haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = np.sin(dlat/2)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon/2)**2
    c = 2 * np.arcsin(np.sqrt(a))
    r = 6371  # Radius of earth in kilometers
    return c * r

def predict_service_charge(pickup_lat, pickup_lon, dropoff_lat, dropoff_lon, pickup_datetime_str):
    """
    Technician ke aane-jaane ka service charge predict karta hai.
    """
    try:
        # Locations ke beech ki doori calculate kar rahe hain using Google Maps API
        distance_km = get_distance_google_maps(float(pickup_lat), float(pickup_lon), float(dropoff_lat), float(dropoff_lon))
        if distance_km is None:
            # Fallback to haversine if Google Maps fails
            distance_km = haversine_distance(float(pickup_lat), float(pickup_lon), float(dropoff_lat), float(dropoff_lon))
            print("Using haversine distance as fallback")

        # Time-related features nikal rahe hain
        # Handle full ISO string by truncating to minutes
        pickup_datetime_str = pickup_datetime_str[:16]  # '2025-09-18T14:48'
        pickup_datetime = datetime.strptime(pickup_datetime_str, '%Y-%m-%dT%H:%M')
        year = pickup_datetime.year
        month = pickup_datetime.month
        weekday = pickup_datetime.weekday()
        hour = pickup_datetime.hour

        # Passenger count hamesha 1 set kar rahe hain
        passenger_count = 1

        # Prediction ke liye DataFrame bana rahe hain
        input_data = {
            'distance': distance_km,
            'year': year,
            'month': month,
            'weekday': weekday,
            'hour': hour,
            'passenger_count': passenger_count
        }
        
        new_data = pd.DataFrame([input_data])
        
        # Categorical variables par one-hot encoding laga rahe hain
        categorical_cols = ['year', 'weekday', 'hour', 'passenger_count']
        for col in categorical_cols:
            for val in new_data[col].unique():
                col_name = f'{col}_{val}'
                if col_name in model_features:
                    new_data[col_name] = 1
                    
        # Model ke training data ke saare columns add kar rahe hain
        for col in model_features:
            if col not in new_data.columns:
                new_data[col] = 0
                
        # Columns ka order sahi kar rahe hain
        new_data = new_data[model_features]
        
        # Model se kiraya predict kar rahe hain
        predicted_fare_usd = model.predict(new_data)[0]

        # USD se INR mein badal rahe hain (exchange rate approx 83 INR per USD)
        exchange_rate = 83.0
        predicted_fare_inr = predicted_fare_usd * exchange_rate

        # Ensure minimum fare
        base_fare_inr = 50.0
        predicted_fare_inr = max(predicted_fare_inr, base_fare_inr)
        
        return predicted_fare_inr, None
    
    except Exception as e:
        print(f"Error during prediction: {e}")
        return None, "Prediction mein koi error aa gayi."

@app.route('/')
def home():
    """Homepage dikha rahe hain"""
    return render_template('index.html', prediction=None)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Form se data le rahe hain
        pickup_lat = request.form.get('pickup_lat')
        pickup_lon = request.form.get('pickup_lon')
        dropoff_lat = request.form.get('dropoff_lat')
        dropoff_lon = request.form.get('dropoff_lon')
        datetime_str = request.form.get('datetime')

        if not all([pickup_lat, pickup_lon, dropoff_lat, dropoff_lon, datetime_str]):
            return render_template('index.html', prediction="Kripya sabhi fields bharein.")

        # Service charge predict kar rahe hain
        predicted_charge, error = predict_service_charge(pickup_lat, pickup_lon, dropoff_lat, dropoff_lon, datetime_str)

        if error:
            return render_template('index.html', prediction=error)

        return render_template('index.html', prediction=f"Andaazit Service Charge: ₹{predicted_charge:.2f}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return render_template('index.html', prediction="An unexpected error occurred.")

@app.route('/predict_fare', methods=['POST'])
def predict_fare():
    try:
        data = request.get_json()
        pickup_lat = data.get('pickup_lat')
        pickup_lon = data.get('pickup_lon')
        dropoff_lat = data.get('dropoff_lat')
        dropoff_lon = data.get('dropoff_lon')
        datetime_str = data.get('datetime')

        if not all([pickup_lat, pickup_lon, dropoff_lat, dropoff_lon, datetime_str]):
            return {"error": "All fields are required"}, 400

        predicted_charge, error = predict_service_charge(pickup_lat, pickup_lon, dropoff_lat, dropoff_lon, datetime_str)

        if error:
            return {"error": error}, 400

        return {"fare": predicted_charge}

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {"error": "An unexpected error occurred"}, 500

if __name__ == '__main__':
    app.run(debug=True)
