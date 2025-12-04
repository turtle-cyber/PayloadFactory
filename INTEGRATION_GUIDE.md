# PayloadFactory Integration Guide

## Architecture Overview

PayloadFactory consists of three main components:

1. **Frontend (React + Vite)** - Located in `payload-frontend/`
2. **Backend (Node.js + Express)** - Located in `payload-backend/`
3. **AIML Engine (Python + FastAPI)** - Located in root directory

## How It Works

### Scan Workflow

```
User uploads ZIP → Node.js Backend → Extract Files → Python AIML Engine
                                                            ↓
Frontend ← Node.js Backend ← MongoDB ← 3-Stage Scan Process
    ↓
Polling for Progress (every 2 seconds)
```

### Three-Stage Scan Process

1. **Stage 1**: Specialized model scanning for vulnerabilities
2. **Stage 2**: LLM classification and exploit generation
3. **Stage 3**: Fuzzing and RL optimization

## Setup Instructions

### Prerequisites

- Node.js (v16 or higher)
- Python (v3.8 or higher)
- MongoDB (running and accessible)

### 1. Install Dependencies

#### Frontend
```bash
cd payload-frontend
npm install
```

#### Backend
```bash
cd payload-backend
npm install
```

#### Python AIML Engine
```bash
pip install -r requirements.txt
```

### 2. Environment Configuration

#### Backend (.env)
Located at `payload-backend/.env`:

```env
MONGO_URI=mongodb://192.168.1.170:27017
MONGO_DB=payloadfactoryDB
MONGO_USERNAME=admin
MONGO_PASSWORD=admin
MONGO_AUTH_SOURCE=admin

# Python FastAPI Backend URL
PYTHON_API_URL=http://localhost:8000

# Optional
PORT=5000
HOST=0.0.0.0
```

#### Frontend
The frontend automatically detects the API URL based on the current hostname.
For custom configuration, create `payload-frontend/.env`:

```env
VITE_API_BASE=http://localhost:5000/api
```

### 3. Start Services

You need to start all three services:

#### 1. Start MongoDB
```bash
# If using Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest

# Or use your existing MongoDB instance
```

#### 2. Start Python AIML Engine
```bash
# From project root
python server/app/main.py
# Or
uvicorn server.app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 3. Start Node.js Backend
```bash
cd payload-backend
npm run dev
# Backend runs on http://localhost:5000
```

#### 4. Start React Frontend
```bash
cd payload-frontend
npm run dev
# Frontend runs on http://localhost:5173 (or next available port)
```

## API Endpoints

### Node.js Backend (Port 5000)

#### Scan Management

- **POST /api/scans/upload** - Upload ZIP and start scan
  - Body: FormData with `zipFile` and scan configuration
  - Returns: `{ success, scan_id, status }`

- **GET /api/scans/:id/status** - Get scan progress
  - Returns: `{ success, data: { scan_id, status, progress, ... } }`

- **POST /api/scans/:id/stop** - Stop running scan
  - Returns: `{ success, message }`

- **GET /api/scans** - Get all scans
  - Returns: `{ success, scan-count, hits: [...] }`

- **GET /api/scans/:id** - Get scan details
  - Returns: `{ success, data: { ... } }`

### Python AIML Engine (Port 8000)

- **POST /start-scan** - Start vulnerability scan
- **GET /scan-status/:scanId** - Get scan status
- **POST /stop-scan/:scanId** - Stop scan
- **GET /health** - Health check

## Features

### ZIP Upload

- Maximum file size: 100MB
- Supported formats: `.zip`
- Files are extracted to temporary directory
- Automatic cleanup after scan

### Progress Polling

- Frontend polls backend every 2 seconds
- Real-time updates on:
  - Current stage (1-3)
  - Files scanned
  - Vulnerabilities found
  - Exploits generated
  - Current file being processed

### Scan Configuration

Users can configure:
- **Application Name**: Project identifier
- **Max Token Length**: 128, 256, 512, 1024, 2048
- **Batch Size**: 8, 16, 32, 64, 128
- **Min Confidence**: 0.1 - 1.0
- **Quick Scan**: Enable for faster scanning
- **Demo Mode**: Use demo data for testing
- **Export Format**: Excel, CSV, JSON, PDF

## Database Schema

### Scans Collection

```javascript
{
  _id: ObjectId,
  project_name: String,
  root_path: String,
  file_size: Number,
  status: String, // pending, stage-1, stage-2, stage-3, completed, failed, cancelled
  progress: {
    current_stage: Number,
    files_scanned: Number,
    total_files: Number,
    vulnerabilities_found: Number,
    exploits_generated: Number,
    current_file: String
  },
  timestamps: {
    submitted_at: String,
    completed_at: String
  },
  stats: Object
}
```

## File Structure

```
PayloadFactoryUX/
├── payload-frontend/          # React Frontend
│   ├── src/
│   │   ├── pages/
│   │   │   └── ScanPage.tsx   # Main scan interface
│   │   ├── utils/
│   │   │   └── http.ts        # API client
│   │   └── ...
│   └── package.json
│
├── payload-backend/           # Node.js Backend
│   ├── src/
│   │   ├── controllers/
│   │   │   └── scan.controller.js  # Scan endpoints
│   │   ├── services/
│   │   │   ├── scan.service.js
│   │   │   └── python-bridge.service.js  # Python API client
│   │   └── routes/
│   │       └── scan.routes.js  # Route definitions
│   └── package.json
│
├── server/                    # Python AIML Engine
│   └── app/
│       ├── main.py           # FastAPI app
│       ├── api/
│       │   └── routes.py     # API routes
│       └── scan_orchestrator.py  # Scan management
│
├── ml_engine/                # AIML Modules
│   ├── vuln_scanner.py
│   ├── exploit_generator.py
│   ├── fuzzing_module.py
│   └── rl_agent.py
│
└── scan_stage_*.py           # Stage execution scripts
```

## Troubleshooting

### Backend can't connect to Python engine

**Error**: `Failed to start scan` or connection refused

**Solution**:
1. Ensure Python FastAPI is running on port 8000
2. Check `PYTHON_API_URL` in backend `.env`
3. Verify no firewall blocking localhost:8000

### MongoDB connection failed

**Error**: `MongoNetworkError` or `ECONNREFUSED`

**Solution**:
1. Ensure MongoDB is running
2. Check `MONGO_URI` in backend `.env`
3. Verify MongoDB credentials

### File upload fails

**Error**: `File too large` or `Only ZIP files allowed`

**Solution**:
1. Ensure file is less than 100MB
2. Use `.zip` format only
3. Check available disk space in temp directory

### Polling not updating

**Solution**:
1. Check browser console for errors
2. Verify backend is returning status updates
3. Ensure scan is actually running (check Python logs)

## Development Tips

### Hot Reload

All three services support hot reload:
- **Frontend**: Vite automatically reloads on file changes
- **Backend**: nodemon watches for changes
- **Python**: uvicorn `--reload` flag enables hot reload

### Testing Scan Flow

1. Create a simple test ZIP file with code
2. Upload via frontend
3. Monitor progress in browser
4. Check backend logs for Python communication
5. Verify scan results in MongoDB

### Adding New Scan Parameters

1. Update frontend form in `ScanPage.tsx`
2. Add field to upload endpoint in `scan.controller.js`
3. Pass to Python bridge service
4. Update Python `/start-scan` endpoint to accept new parameter

## Security Considerations

- ZIP files are validated before extraction
- Extracted files are stored in temporary directories with unique names
- Scan processes run in isolated Python subprocesses
- File size limits prevent DOS attacks
- Input validation on all endpoints

## Performance Optimization

- Use `quick_scan` option for faster scanning
- Adjust `batch_size` based on available memory
- Consider running Python engine on separate server for production
- Implement caching for repeated scans of same files

## Future Enhancements

- [ ] Real-time WebSocket updates instead of polling
- [ ] Scan history and comparison
- [ ] Multiple file format support (tar.gz, etc.)
- [ ] Scan queue management
- [ ] User authentication and authorization
- [ ] Scan result export and reporting
- [ ] Docker Compose for easy deployment
