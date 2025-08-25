from app import app

# Vercel requires this to be named 'app' for serverless functions
app = app

# Optional: Add this for Vercel serverless compatibility
if __name__ == "__main__":
    app.run()