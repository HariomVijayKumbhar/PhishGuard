import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import Jimp from 'jimp';
import QRCode from 'qrcode';
import {
  decodeQrFromImage,
  analyzeQuishedUrl,
  defangPayload,
  QR_LIMITS,
  scanAttachmentsForQr
} from '../src/services/qrPhishingService.js';

/**
 * Helper: build a PNG buffer containing a QR code encoding `payload`
 */
async function makeQrImageBuffer(payload) {
  const qrPng = await QRCode.toBuffer(payload, { type: 'png', width: 240, margin: 2 });
  return qrPng;
}

describe('Quishing (QR Code Phishing) Engine', () => {
  test('decodes a QR code from an in-memory PNG image buffer', async () => {
    const buffer = await makeQrImageBuffer('https://paypa1-secure-login.com/verify');
    const decoded = await decodeQrFromImage(buffer);
    assert.equal(decoded.rawText, 'https://paypa1-secure-login.com/verify');
  });

  test('rejects oversized image payloads (decompression-bomb guard)', async () => {
    const tiny = await makeQrImageBuffer('https://example.com');
    // Fake a buffer beyond the raw byte limit
    const bigBuffer = Buffer.concat([tiny, Buffer.alloc(QR_LIMITS.MAX_IMAGE_BYTES)]);
    await assert.rejects(
      () => decodeQrFromImage(bigBuffer),
      (err) => err.code === 'IMAGE_TOO_LARGE'
    );
  });

  test('rejects images with no QR code (422)', async () => {
    // Plain solid-color PNG without QR
    const plain = new Jimp(200, 200, 0xffffffff);
    const buf = await plain.getBufferAsync('image/png');
    await assert.rejects(
      () => decodeQrFromImage(buf),
      (err) => err.code === 'NO_QR_FOUND'
    );
  });

  test('flags lookalike domain QR destination as highly suspicious', () => {
    const analysis = analyzeQuishedUrl('https://paypa1-secure-login.com/verify-account');
    assert.ok(analysis.verdict === 'MALICIOUS' || analysis.verdict === 'SUSPICIOUS');
    assert.ok(analysis.lookalike);
    assert.equal(analysis.lookalike.brand, 'PayPal');
    assert.ok(analysis.threatScore >= 40);
  });

  test('flags URL-shortener QR destinations as suspicious', () => {
    const analysis = analyzeQuishedUrl('https://bit.ly/3xYzAbc');
    assert.equal(analysis.isShortener, true);
    assert.ok(analysis.indicators.some(i => i.type === 'qr_shortener'));
  });

  test('flags raw-IP QR destinations', () => {
    const analysis = analyzeQuishedUrl('http://198.51.100.24/login');
    assert.ok(analysis.indicators.some(i => i.type === 'qr_raw_ip'));
    assert.ok(analysis.threatScore >= 35);
  });

  test('benign QR destinations score low with no indicators', () => {
    const analysis = analyzeQuishedUrl('https://github.com/phishguard/phishguard/pull/42');
    assert.equal(analysis.verdict, 'BENIGN');
    assert.equal(analysis.isShortener, false);
    assert.equal(analysis.lookalike, null);
  });

  test('defangs payloads for safe display', () => {
    assert.equal(defangPayload('https://evil.com/login'), 'hxxp[://]evil[.]com/login');
  });

  test('scans email attachments for embedded QR codes', async () => {
    const qrPng = await makeQrImageBuffer('https://paypa1-verify.com/authenticator/reset');
    const findings = await scanAttachmentsForQr([
      { filename: 'mfa-reset.png', contentType: 'image/png', content: qrPng },
      { filename: 'readme.txt', contentType: 'text/plain', content: Buffer.from('no qr here') }
    ]);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].filename, 'mfa-reset.png');
    assert.ok(findings[0].analysis.lookalike || findings[0].analysis.verdict !== 'BENIGN');
  });
});
