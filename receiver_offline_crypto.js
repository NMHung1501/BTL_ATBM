function textToBytes(str){
  return new TextEncoder().encode(str);
}

function bytesToHex(arr){
  return Array.from(arr).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function unpadPkcs7(padded){
  const padLen = padded[padded.length-1];
  if(padLen<1 || padLen>16) throw new Error('Invalid PKCS#7 padding');
  for(let i=padded.length-padLen;i<padded.length;i++){
    if(padded[i]!==padLen) throw new Error('Invalid PKCS#7 padding');
  }
  return padded.slice(0,padded.length-padLen);
}

function b64ToBytes(b64){
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
  return out;
}

async function sha512Hex(bytes){
  const digest = await crypto.subtle.digest('SHA-512', bytes);
  return bytesToHex(new Uint8Array(digest));
}

async function aes256CbcDecryptPkcs7(encBytes, keyBytes32, ivBytes16){
  const key = await crypto.subtle.importKey(
    'raw', keyBytes32, {name:'AES-CBC'}, false, ['decrypt']
  );
  const decrypted = await crypto.subtle.decrypt(
    {name:'AES-CBC', iv: ivBytes16}, key, encBytes
  );
  
  // Directly return the decrypted array
  return new Uint8Array(decrypted); 
}

function rsaVerifyMetadataSha512Pkcs1v15(metadataBytes, signatureBytes, senderPublicKeyPem){
  // 1. Chuyển đổi an toàn Uint8Array sang chuỗi nhị phân (binary string)
  let mdBin = '';
  for(let i = 0; i < metadataBytes.length; i++) {
    mdBin += String.fromCharCode(metadataBytes[i]);
  }

  let sigBin = '';
  for(let i = 0; i < signatureBytes.length; i++) {
    sigBin += String.fromCharCode(signatureBytes[i]);
  }

  // 2. Tạo mã băm SHA-512 từ chuỗi nhị phân chuẩn
  const md = forge.md.sha512.create();
  md.update(mdBin);

  // 3. Thực hiện xác minh chữ ký RSA
  const pubKey = forge.pki.publicKeyFromPem(senderPublicKeyPem);
  return pubKey.verify(md.digest().bytes(), sigBin);
}

function rsaDecryptPkcs1v15(encBytes, receiverPrivateKeyPem){
  const privKey = forge.pki.privateKeyFromPem(receiverPrivateKeyPem);
  // forge expects encrypted as bytes.
  const encBytesArr = forge.util.binary.raw.encode(encBytes);
  // easier: convert Uint8Array to binary string
  let bin='';
  for(let i=0;i<encBytes.length;i++) bin += String.fromCharCode(encBytes[i]);

  // PKCS#1 v1.5 decryption with a sentinel: use forge's privateKey.decrypt? not provided directly.
  // Implement by raw RSA (m) and then parse padding per PKCS#1 v1.5.
  const k = privKey.n.bitLength();
  // forge internal raw decryption
  const decrypted = privKey.decrypt(bin, 'RSAES-PKCS1-V1_5');
  // decrypted is a binary string
  const out = new Uint8Array(decrypted.length);
  for(let i=0;i<decrypted.length;i++) out[i]=decrypted.charCodeAt(i);
  return out;
}

function metadataDeterministicBytes(filename, expIso){
  const metadata = {filename, exp: expIso};
  const text = JSON.stringify(metadata, Object.keys(metadata).sort());
  // The above doesn't match sort_keys separators behavior.
  // We'll reproduce deterministically like python:
  const keys = ['exp','filename'];
  const objText = '{' + keys.map(k=>`"${k}":${JSON.stringify(metadata[k])}`).join(',') + '}';
  // Need to match separators (",":") and no spaces.
  // objText above already no spaces.
  return textToBytes(objText);
}