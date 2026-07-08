const { spawn } = require('child_process');
const path = require('path');

console.log('==========================================');
console.log('   Starting ICS AASG Threat Modeler       ');
console.log('==========================================');

const backendDir = path.join(__dirname, 'backend');
const frontendDir = path.join(__dirname, 'frontend');

// Determine Python path
const pythonPath = process.platform === 'win32'
  ? path.join(backendDir, '.venv', 'Scripts', 'python.exe')
  : path.join(backendDir, '.venv', 'bin', 'python');

// Start Backend
console.log('Starting Backend FastAPI Server...');
const backendProcess = spawn(`"${pythonPath}"`, ['main.py'], {
  cwd: backendDir,
  shell: true,
  stdio: 'inherit'
});

// Start Frontend
console.log('Starting Frontend Vite Dev Server...');
const frontendProcess = spawn('npm', ['run', 'dev'], {
  cwd: frontendDir,
  shell: true,
  stdio: 'inherit'
});

// Handle termination
process.on('SIGINT', () => {
  console.log('\nStopping servers...');
  backendProcess.kill();
  frontendProcess.kill();
  process.exit(0);
});
