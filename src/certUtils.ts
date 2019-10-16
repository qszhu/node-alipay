///<reference path='x509.d.ts' />

import * as fs from 'fs';
import * as crypto from 'crypto';
import { promisify } from 'util';

import * as x509 from 'x509';
import { file } from 'tmp-promise';

export async function readPublicKey(keyPath: string) {
  const data = await promisify(fs.readFile)(keyPath);
  return crypto.createPublicKey(data.toString());
}

export async function readPrivateKey(keyPath: string) {
  const data = await promisify(fs.readFile)(keyPath);
  const key = Buffer.from(data.toString(), 'base64');
  return crypto.createPrivateKey({
    key,
    format: 'der',
    type: 'pkcs8',
  });
}

function md5(msg: string) {
  const hash = crypto.createHash('md5');
  hash.update(msg);
  return hash.digest('hex');
}

function getCertSNParsed(cert: {
  issuer: {
    countryName: string;
    organizationName: string;
    organizationalUnitName: string;
    commonName: string;
  };
  serial: string;
}) {
  const { countryName, organizationName, organizationalUnitName, commonName } = cert.issuer;
  const issuer = `CN=${commonName},OU=${organizationalUnitName},O=${organizationName},C=${countryName}`;
  const serial = BigInt(`0x${cert.serial}`).toString();
  const msg = `${issuer}${serial}`;
  return md5(msg);
}

export function getCertSN(certPath: string) {
  const cert = x509.parseCert(certPath);
  return getCertSNParsed(cert);
}

async function readPemCertChain(cert: string) {
  const pattern = /(-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----)/g;
  const blocks = cert.match(pattern)!;
  const res = [];
  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];
    const { fd, path, cleanup } = await file();
    await promisify(fs.writeFile)(path, block);
    try {
      const cert = x509.parseCert(path);
      res.push(cert);
    } catch (err) {
      // console.error(err)
    } finally {
      cleanup();
    }
  }
  return res;
}

export async function getRootCertSN(certPath: string) {
  const data = await promisify(fs.readFile)(certPath);
  const certs = await readPemCertChain(data.toString());
  return certs
    .filter(cert => cert.signatureAlgorithm.toLowerCase().includes('rsaencryption'))
    .map(cert => getCertSNParsed(cert))
    .join('_');
}
