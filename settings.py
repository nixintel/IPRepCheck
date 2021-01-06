from dotenv import load_dotenv
import os


# Load API keys from .env file

load_dotenv()

aipdb_key = os.getenv('AIPDB_KEY')


