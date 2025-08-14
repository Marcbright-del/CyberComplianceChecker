# core/scanner.py
import requests
from django.conf import settings

class CloudScanner:
    def __init__(self):
        self.api_key = settings.SCANNER_API_KEY
        # This is the real API endpoint for IPQualityScore's IP reputation check
        self.api_url_template = f'https://www.ipqualityscore.com/api/json/ip/{self.api_key}/'

    def run_scan(self, target_ip):
        # Construct the full URL with the target IP address
        full_api_url = self.api_url_template + target_ip

        try:
            # Make the real API call to the external service
            response = requests.get(full_api_url, timeout=15)
            response.raise_for_status() # Raises an exception for bad status codes (4xx or 5xx)

            # Parse the JSON data from the response
            result = response.json()

            if result.get('success'):
                # Convert their risk score (0-100) to our compliance score (100-0)
                risk_score = result.get('fraud_score', 100)
                compliance_score = 100 - risk_score

                # Determine a risk level based on the score
                risk_level = "Low"
                if compliance_score < 60:
                    risk_level = "High"
                elif compliance_score < 80:
                    risk_level = "Medium"

                return {"score": compliance_score, "risk": risk_level}
            else:
                # Handle cases where the API call was successful but the service reported an error
                print(f"API service returned an error: {result.get('message')}")
                return {"score": 0, "risk": "API Error"}

        except requests.exceptions.RequestException as e:
            print(f"API request failed: {e}")
            # If the API call fails, return a default error state
            return {"score": 0, "risk": "Network Error"}