const fs = require('node:fs');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { pipeline } = require('node:stream/promises');
const [input, output, expected] = process.argv.slice(2);
async function main() {
  const hash = crypto.createHash('sha256');
  for await (const part of fs.createReadStream(input)) hash.update(part);
  if (hash.digest('hex') !== expected.toLowerCase()) throw new Error('Official compressed checksum mismatch');
  await pipeline(fs.createReadStream(input), zlib.createZstdDecompress(), fs.createWriteStream(output, { flags: 'wx' }));
  const payload = crypto.createHash('sha256');
  for await (const part of fs.createReadStream(output)) payload.update(part);
  console.log(JSON.stringify({ sha256: payload.digest('hex'), size: fs.statSync(output).size }));
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
