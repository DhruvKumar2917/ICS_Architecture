const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('==========================================');
console.log('   Setting up ICS AASG Threat Modeler     ');
console.log('==========================================');

try {
  // 1. Setup Backend
  console.log('\n[1/2] Setting up Python virtual environment and backend dependencies...');
  const backendDir = path.join(__dirname, 'backend');
  
  // Create venv if it doesn't exist
  const venvDir = path.join(backendDir, '.venv');
  if (!fs.existsSync(venvDir)) {
    execSync('python -m venv .venv', { cwd: backendDir, stdio: 'inherit' });
  }
  
  // Install requirements
  const pipPath = process.platform === 'win32' 
    ? path.join(venvDir, 'Scripts', 'pip.exe')
    : path.join(venvDir, 'bin', 'pip');
  
  execSync(`"${pipPath}" install -r requirements.txt`, { cwd: backendDir, stdio: 'inherit' });

  // 2. Setup Frontend
  console.log('\n[2/2] Installing frontend npm packages...');
  const frontendDir = path.join(__dirname, 'frontend');
  execSync('npm install', { cwd: frontendDir, stdio: 'inherit' });

  console.log('\n==========================================');
  console.log(' Setup Complete! Run "npm start" to run.');
  console.log('==========================================');
} catch (error) {
  console.error('Setup failed:', error);
  process.exit(1);
}
