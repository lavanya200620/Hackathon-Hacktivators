import nacl from 'tweetnacl';
import { readFileSync } from 'fs';

function hexToUint8Array(hexString) {
  const cleanHex = hexString.replace(/^0x/, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes;
}

const fileContent = readFileSync('./src/services/ledgerStorage.js', 'utf8');

// Extract seed records
const seeds = [
  {
    id: 'SRC-98214',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    sig: '9d5ad770fdfea75d151c1b582fbff78e5b5deb46ca56aef76db4f6b3152e99331bd6d70241b992cf2f4fcbcc485197f422fa6f7e45c8650c7646b36a712c810a',
    pub: '2a71a70705363c8fd0e154e5ac0386725dba39fdc8d175f9cf688ffd63af4a9f'
  },
  {
    id: 'SRC-77402',
    hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    sig: '34a9a086a084ee48bce427ca1c1a0413f86733076230b1c3f84ab8edf41d6613e7eab4ce9025fc2b83904ff4a0751dbb5dda0732b0226c0c56ec71498933270b',
    pub: 'a19b169bb061b6f37bef103a0049f43f5451c958dfcbf4222deeeb2685f26b51'
  },
  {
    id: 'SRC-55109',
    hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    sig: '0fdcc5b4f5b9b81f1b5e59309282dfccedd735ba542270bf57d30281d506d6f433811ff40603900d5f4f0501c41fa34c90f46f9a8de18e151236f35fd62e6c04',
    pub: '1d4cbe1ad10ab20738f35f97fc446a9dcddd82a5297ab807647805c5f8f91420'
  }
];

let allPass = true;
seeds.forEach(s => {
  const valid = nacl.sign.detached.verify(
    hexToUint8Array(s.hash),
    hexToUint8Array(s.sig),
    hexToUint8Array(s.pub)
  );
  console.log(`Seed ${s.id} Ed25519 verification:`, valid ? 'PASS (Valid)' : 'FAIL');
  if (!valid) allPass = false;
});

console.log('All Seed Signatures Valid:', allPass);

