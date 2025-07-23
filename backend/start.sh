#!/bin/bash
echo "🚀 Starting CTI Dashboard..."

# Start backend
cd backend
source venv/bin/activate 2>/dev/null || python3 -m venv venv && source venv/bin/activate
pip install -q Flask Flask-CORS python-dotenv requests gunicorn
python app.py &
BACKEND_PID=$!

# Start frontend  
cd ../frontend
npm install -q
npm start &
FRONTEND_PID=$!

echo "✅ CTI Dashboard started!"
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo "Access at: http://localhost:3000"

# Wait for user input to stop
read -p "Press Enter to stop servers..."
kill $BACKEND_PID $FRONTEND_PID
