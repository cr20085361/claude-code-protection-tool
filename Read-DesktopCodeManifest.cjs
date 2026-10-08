// Read public vendor metadata without executing installed application code.
const fs = require('node:fs');
const crypto = require('node:crypto');
const archive = process.argv[2];
if (!archive) throw new Error('Expected installed app.asar path');
const fd = fs.openSync(archive, 'r');
try {
  const header = Buffer.alloc(16);
  fs.readSync(fd, header, 0, 16, 0);
  const raw = Buffer.alloc(header.readUInt32LE(12));
  fs.readSync(fd, raw, 0, raw.length, 16);
  const tree = JSON.parse(raw.toString());
  const offset = 8 + header.readUInt32LE(4);
  let found;
  for (const [name, entry] of Object.entries(tree.files['.vite'].files.build.files)) {
    if (!name.endsWith('.js') || entry.unpacked) continue;
    const buffer = Buffer.alloc(entry.size);
    fs.readSync(fd, buffer, 0, buffer.length, offset + Number(entry.offset));
    const source = buffer.toString();
    // Vendor minification changes function names between releases. Read only JSON
    // data, without evaluating any JavaScript from the installed application.
    const candidates = [...source.matchAll(/JSON\.parse\('(\{"version":[\s\S]*?)'\)/g)]
      .map(match => { try { return JSON.parse(match[1]); } catch { return null; } })
      .filter(value => value?.manifest?.platforms?.['win32-x64'] && value.baseUrl);
    if (!candidates.length) continue;
    if (candidates.length !== 1) throw new Error('Ambiguous embedded Code manifests');
    const manifest = candidates[0];
    if (!/^\d+\.\d+\.\d+$/.test(manifest.version)
        || manifest.manifest.version !== manifest.version
        || !/^https:\/\/downloads\.claude\.ai\/claude-code-releases(?:\/rc\/[a-f0-9]{40})?$/.test(manifest.baseUrl)
        || manifest.manifest.platforms['win32-x64'].binary !== 'claude.exe.zst'
        || !/^[a-f0-9]{64}$/.test(manifest.manifest.platforms['win32-x64'].checksum)) {
      throw new Error('Unexpected official Code manifest schema or source');
    }
    found = {
      desktopCodeVersion: manifest.version,
      baseUrl: manifest.baseUrl,
      platform: manifest.manifest.platforms['win32-x64'],
      sourceChunk: name,
      sourceChunkSha256: crypto.createHash('sha256').update(buffer).digest('hex'),
      msixAutomaticCodeUpdatesDisabled: source.includes('[CCD-autoupdate] Disabled: MSIX install'),
      desktopUpdatePolicySupported: source.includes('flatKey:"disableAutoUpdates"'),
    };
    break;
  }
  if (!found) throw new Error('Pinned Code manifest not found; review this app version');
  process.stdout.write(JSON.stringify(found));
} finally { fs.closeSync(fd); }
