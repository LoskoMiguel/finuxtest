from dotenv import load_dotenv
import os

load_dotenv()

class Settings:
    HOST = os.getenv("HOST")
    DBPORT = os.getenv("DBPORT")
    DBNAME = os.getenv("DBNAME")
    USER = os.getenv("USER")
    PASSWORD = os.getenv("PASSWORD")
    PORT = os.getenv("PORT")

settings = Settings()
