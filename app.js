const express = require('express');
const bodyParser = require('body-parser');
const base64url = require('base64url');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

let users = [];

app.use(bodyParser.json());
app.use(express.static('public'));

const generateRandomBuffer = (size) => crypto.randomBytes(size);
const generateChallenge = () => base64url(generateRandomBuffer(32));

const base64ToBuffer = (base64) => Buffer.from(base64, 'base64');

app.get('/', (_, res) => {
  res.sendFile(__dirname + '/public/index.html');
});


app.post('/register', (req, res) => {
  const { username } = req.body;

  const user = users.find(u => u.username === username);
  if (user) {
    return res.status(400).json({ error: 'User already exists' });
  }

  const challenge = generateChallenge();
  users.push({ username, challenge });

  const publicKeyCredentialCreationOptions = {
    challenge: challenge,
    rp: { name: "Simple WebAuthn App" },
    user: {
      id: base64url.encode(crypto.randomBytes(32)),
      name: username,
      displayName: username
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    attestation: "direct",
    authenticatorSelection: {
      authenticatorAttachment: "platform", // Specify platform authenticator (e.g., Touch ID, Face ID)
      requireResidentKey: false,
      userVerification: "required"
    }
  };

  res.json(publicKeyCredentialCreationOptions);
});

app.post('/register/verify', (req, res) => {
  const { username, attestation } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  const expectedChallenge = user.challenge;
  const clientDataJSON = base64ToBuffer(attestation.response.clientDataJSON);
  const clientData = JSON.parse(clientDataJSON.toString());

  if (clientData.challenge !== expectedChallenge) {
    return res.status(400).json({ error: 'Challenges do not match' });
  }

  user.credentials = user.credentials || [];
  user.credentials.push({
    id: attestation.id,
    publicKey: attestation.response.attestationObject
  });

  res.json({ status: 'ok' });
});

app.post('/login', (req, res) => {
  const { username } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  const challenge = generateChallenge();
  user.challenge = challenge;

  const publicKeyCredentialRequestOptions = {
    challenge: challenge,
    allowCredentials: user.credentials.map(cred => ({
      id: cred.id,
      type: 'public-key'
    })),
    userVerification: 'required'
  };

  res.json(publicKeyCredentialRequestOptions);
});

app.post('/login/verify', (req, res) => {
  const { username, assertion } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  const expectedChallenge = user.challenge;
  const clientDataJSON = base64ToBuffer(assertion.response.clientDataJSON);
  const clientData = JSON.parse(clientDataJSON.toString());

  if (clientData.challenge !== expectedChallenge) {
    return res.status(400).json({ error: 'Challenges do not match' });
  }

  res.json({ status: 'ok' });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
