import nacl from 'tweetnacl';

function bufferToHex(buffer) {
  const byteArray = new Uint8Array(buffer);
  return Array.from(byteArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToUint8Array(hexString) {
  const cleanHex = hexString.replace(/^0x/, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes;
}

const seeds = [
  { id: 'SRC-98214', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  { id: 'SRC-77402', hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' },
  { id: 'SRC-55109', hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' },
];

const results = seeds.map(s => {
  const kp = nacl.sign.keyPair();
  const pubHex = bufferToHex(kp.publicKey);
  const secHex = bufferToHex(kp.secretKey);
  const msgBytes = hexToUint8Array(s.hash);
  const sigBytes = nacl.sign.detached(msgBytes, kp.secretKey);
  const sigHex = bufferToHex(sigBytes);
  const valid = nacl.sign.detached.verify(msgBytes, sigBytes, kp.publicKey);
  const keyId = `ED25519-${pubHex.substring(0, 8).toUpperCase()}`;

  return {
    id: s.id,
    hash: s.hash,
    publicKeyHex: pubHex,
    secretKeyHex: secHex,
    signatureHex: sigHex,
    keyId,
    verified: valid,
  };
});

console.log(JSON.stringify(results, null, 2));

