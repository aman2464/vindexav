const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { spawn } = require('child_process');

let mainWindow;
let backendProcess;

function resolveBackendPath() {
  const possiblePaths = [
    path.join('/opt/VindexAV/resources/vindexav-core/vindexav-core'),
    path.join(process.resourcesPath, 'vindexav-core', 'vindexav-core'),
    path.join(__dirname, '../dist/vindexav-core/vindexav-core'),
    path.join(__dirname, '../../dist/vindexav-core/vindexav-core'),
    path.join(process.cwd(), 'dist/vindexav-core/vindexav-core')
  ];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function startBackend() {
  const binary = resolveBackendPath();
  const logDir = path.join(app.getPath('home'), '.vindexav');
  fs.mkdirSync(logDir, { recursive: true });
  const logFile = path.join(logDir, 'backend_exec.log');
  const out = fs.openSync(logFile, 'a');

  if (!binary) {
    fs.appendFileSync(logFile, `[ERROR] vindexav-core binary not found.\n`);
    return;
  }

  try {
    fs.chmodSync(binary, '755');
  } catch (e) {}

  try {
    const workingDir = path.dirname(binary);
    fs.appendFileSync(logFile, `[INFO] Spawning: ${binary}\n`);

    backendProcess = spawn(binary, [], {
      cwd: workingDir,
      detached: false,
      stdio: ['ignore', out, out]
    });

    backendProcess.on('error', (err) => {
      fs.appendFileSync(logFile, `[ERROR] Spawn error: ${err.message}\n`);
    });
  } catch (err) {
    fs.appendFileSync(logFile, `[CRITICAL] Spawn thrown: ${err.message}\n`);
  }
}

function waitForServer(callback, retries = 100) {
  if (retries <= 0) {
    console.error('Backend connection timed out.');
    callback();
    return;
  }

  const req = http.get('http://127.0.0.1:8000/api/status', (res) => {
    if (res.statusCode === 200) {
      callback();
    } else {
      setTimeout(() => waitForServer(callback, retries - 1), 300);
    }
  });

  req.on('error', () => {
    setTimeout(() => waitForServer(callback, retries - 1), 300);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1240,
    height: 820,
    minWidth: 950,
    minHeight: 650,
    title: 'VindexAV Endpoint Security',
    icon: path.join(__dirname, 'public/logo.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    },
    backgroundColor: '#0c1017',
    autoHideMenuBar: true
  });

  mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html')).catch((err) => {
    console.error('Failed to load UI:', err);
  });
}

// Dedicated handlers for file vs directory
ipcMain.handle('dialog:openFile', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    title: 'Select File to Scan'
  });
  return canceled || filePaths.length === 0 ? null : filePaths[0];
});

ipcMain.handle('dialog:openDirectory', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Select Folder to Scan'
  });
  return canceled || filePaths.length === 0 ? null : filePaths[0];
});

app.whenReady().then(() => {
  startBackend();
  waitForServer(() => createWindow());
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('will-quit', () => {
  if (backendProcess) {
    try {
      backendProcess.kill('SIGTERM');
    } catch (e) {}
  }
});