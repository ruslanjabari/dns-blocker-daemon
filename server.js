const dns = require('native-dns');
const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');
const { execSync } = require('child_process');
const algorithm = 'aes-256-ctr';

function storeKeyInKeychain(key, keyName) {
  execSync(`security add-generic-password -a "${keyName}" -s "${keyName}" -w "${key}" -U`);
}

function retrieveKeyFromKeychain(keyName) {
  try {
    return execSync(`security find-generic-password -a "${keyName}" -s "${keyName}" -w`).toString().trim();
  } catch (error) {
    console.error('Error retrieving key from Keychain:', error);
    return null;
  }
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const keyName = 'dns_blocker_key';
const isFirstRun = !fs.existsSync('password.enc');

if (isFirstRun) {
  const password = crypto.randomBytes(16).toString('hex');
  const encryptionKey = crypto.randomBytes(32).toString('hex');

  // Encryption function with IV
  function encrypt(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
  }

  const encryptedPassword = encrypt(password, encryptionKey);
  fs.writeFileSync('password.enc', encryptedPassword);

  storeKeyInKeychain(encryptionKey, keyName);
  console.log('Daemon initialized. Encryption key stored in Keychain.');
} else {
  console.log('Daemon restarted.');
}

function hashWebsite(site) {
  return crypto.createHash('sha256').update(site).digest('hex');
}

function loadBlockedSites() {
  if (fs.existsSync('blockedSites.json')) {
    return JSON.parse(fs.readFileSync('blockedSites.json', 'utf8'));
  }
  return {};
}

function saveBlockedSites(blockedSites) {
  fs.writeFileSync('blockedSites.json', JSON.stringify(blockedSites, null, 2));
}

let blockedSites = loadBlockedSites();

function blockSite(site, duration) {
  const hashedSite = hashWebsite(site);
  const unblockTime = Date.now() + duration;
  blockedSites[hashedSite] = unblockTime;
  saveBlockedSites(blockedSites);
}

setInterval(() => {
  const now = Date.now();
  Object.keys(blockedSites).forEach(siteHash => {
    if (blockedSites[siteHash] < now) {
      delete blockedSites[siteHash];
    }
  });
  saveBlockedSites(blockedSites);
}, 60000);

const server = dns.createServer();

server.on('request', function (request, response) {
  const requestedDomain = request.question[0].name;
  const hashedDomain = hashWebsite(requestedDomain);

  if (blockedSites.hasOwnProperty(hashedDomain)) {
    response.answer.push(dns.A({
      name: requestedDomain,
      address: '0.0.0.0',
      ttl: 600,
    }));
  }

  response.send();
});

server.on('error', function (err, buff, req, res) {
  console.error(err.stack);
});

server.serve(53);
console.log('DNS Server running at 127.0.0.1:53');

rl.on('line', (input) => {
  const [command, arg1, arg2] = input.split(' ');

  if (command === 'stop') {
  // Decryption function with IV
  function decrypt(text, key) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }


    const encryptedPassword = fs.readFileSync('password.enc', 'utf8');
    const encryptionKey = retrieveKeyFromKeychain(keyName);

    if (encryptionKey) {
      const decryptedPassword = decrypt(encryptedPassword, encryptionKey);

      if (arg1 === decryptedPassword) {
        console.log('Password correct. Stopping daemon...');
        process.exit(0);
      } else {
        console.log('Incorrect password.');
      }
    } else {
      console.log('Unable to retrieve encryption key.');
    }
  } else if (command === 'block') {
    blockSite(arg1, parseInt(arg2));
    console.log(`Blocking ${arg1} for ${arg2} milliseconds.`);
  } else {
    console.log('Unknown command.');
  }
});
