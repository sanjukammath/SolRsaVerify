const NodeRSA = require('node-rsa');

const RSAVerify = artifacts.require('SolRsaVerify');

const exponent =
  '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001';

contract('SolRSAVerify', accounts => {
  beforeEach(async function() {
    this.verification = await RSAVerify.new();
  });

  describe('verification', function() {
    describe('when signature is correct', function() {
      it('verifies', async function() {
        const key = new NodeRSA({ b: 1024 });
        const text = 'hello world';

        const sign = key.sign(text, 'hex');
        const publicComponents = key.exportKey('components-public');

        const message = web3.utils.asciiToHex(text);
        const base = '0x' + sign.toString('hex');
        const modulus = '0x' + publicComponents.n.toString('hex', 1);

        //   console.log('base: ', base);
        //   console.log('modulus: ', modulus);
        //   console.log('exponent: ', exponent);
        //   console.log('message: ', message);

        const result = await this.verification.pkcs1Sha256VerifyRaw(
          message,
          base,
          exponent,
          modulus
        );
        assert.equal(result, 0);
      });
    });

    describe('when signature is using different signing and hashing scheme', function() {
      it('code 1', async function() {
        const key = new NodeRSA({ b: 1024 });
        const text = 'hello world';

        key.setOptions({
          signingScheme: 'pss-sha1'
        });

        const sign = key.sign(text, 'hex');
        const publicComponents = key.exportKey('components-public');

        const message = web3.utils.asciiToHex(text);
        const base = '0x' + sign.toString('hex');
        const modulus = '0x' + publicComponents.n.toString('hex', 1);
        const exponent =
          '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001';

        //   console.log('base: ', base);
        //   console.log('modulus: ', modulus);
        //   console.log('exponent: ', exponent);
        //   console.log('message: ', message);

        const result = await this.verification.pkcs1Sha256VerifyRaw(
          message,
          base,
          exponent,
          modulus
        );

        assert.equal(result, 1);
      });
    });

    describe('when signature is using same signing scheme but md5 hashing', function() {
      it('code 3', async function() {
        const key = new NodeRSA({ b: 1024 });
        const text = 'hello world';

        key.setOptions({
          signingScheme: 'pkcs1-md5'
        });

        const sign = key.sign(text, 'hex');
        const publicComponents = key.exportKey('components-public');

        const message = web3.utils.asciiToHex(text);
        const base = '0x' + sign.toString('hex');
        const modulus = '0x' + publicComponents.n.toString('hex', 1);
        const exponent =
          '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001';

        //   console.log('base: ', base);
        //   console.log('modulus: ', modulus);
        //   console.log('exponent: ', exponent);
        //   console.log('message: ', message);

        const result = await this.verification.pkcs1Sha256VerifyRaw(
          message,
          base,
          exponent,
          modulus
        );

        assert.equal(result, 3);
      });
    });

    describe('when signature is for different text', function() {
      it('code 5', async function() {
        const key = new NodeRSA({ b: 1024 });
        const text = 'hello world';

        //signing something else
        const sign = key.sign('something else', 'hex');
        const publicComponents = key.exportKey('components-public');

        const message = web3.utils.asciiToHex(text);
        const base = '0x' + sign.toString('hex');
        const modulus = '0x' + publicComponents.n.toString('hex', 1);
        const exponent =
          '0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001';

        const result = await this.verification.pkcs1Sha256VerifyRaw(
          message,
          base,
          exponent,
          modulus
        );
        assert.equal(result, 5);
      });
    });
  });
});
