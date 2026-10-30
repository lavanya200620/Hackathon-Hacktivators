import nacl from 'tweetnacl';

function hexToUint8Array(hexString) {
  const cleanHex = hexString.replace(/^0x/, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes;
}

const seedSource1 = {
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  signature: '7a83d4c6f50b9123847289abcf123894723894bcefa012938471203948abcdf1982347102938471029384710293847102938471029384710293847102938471a',
  publicKey: 'a9103847bce12830948120938471029384710293847102938471029384710293',
};

try {
  const msgBytes = hexToUint8Array(seedSource1.sha256);
  const sigBytes = hexToUint8Array(seedSource1.signature);
  const pubBytes = hexToUint8Array(seedSource1.publicKey);
  const valid = nacl.sign.detached.verify(msgBytes, sigBytes, pubBytes);
  console.log('Seed Source 1 signature mathematically valid with its seed publicKey:', valid);
} catch (e) {
  console.log('Seed Source 1 verify error:', e.message);
}

