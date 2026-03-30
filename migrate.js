const fs = require('fs');
const path = require('path');

const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir);
  console.log('Created public dir');
}

const files = fs.readdirSync(__dirname);
let moved = 0;
for (const file of files) {
  if (file.endsWith('.html')) {
    fs.renameSync(path.join(__dirname, file), path.join(publicDir, file));
    console.log(`Moved ${file}`);
    moved++;
  }
}
console.log(`Successfully moved ${moved} HTML files.`);
