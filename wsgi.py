# wsgi.py
from sis_app import app

# Vercel requires the app variable to be named 'app'
app = app

if __name__ == "__main__":
    app.run()