declare module 'x509' {
  function parseCert(
    path: string,
  ): {
    issuer: {
      countryName: string;
      organizationName: string;
      organizationalUnitName: string;
      commonName: string;
    };
    serial: string;
    signatureAlgorithm: string;
  };
}
