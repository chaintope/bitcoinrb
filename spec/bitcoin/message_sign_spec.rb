require 'spec_helper'

RSpec.describe Bitcoin::MessageSign, network: :mainnet do

  # bitcoinjs-lib fixtures.
  let(:fixtures) { fixture_file('message_signs.json') }

  shared_examples "test valid spec" do
    it do
      valid['sign'].each do |v|
        key = Bitcoin::Key.new(priv_key: ECDSA::Format::IntegerOctetString.encode(v['d'].to_i, 32).bth, compressed: false)
        signature = Bitcoin::MessageSign.sign_message(key, v['message'], prefix: prefix(v['network']))
        expect(signature).to eq(v['signature'])
        if v['compressed']
          key = Bitcoin::Key.new(priv_key: ECDSA::Format::IntegerOctetString.encode(v['d'].to_i, 32).bth)
          signature = Bitcoin::MessageSign.sign_message(key, v['message'], prefix: prefix(v['network']))
          expect(signature).to eq(v['compressed']['signature'])
        end
      end
      valid['verify'].select{|v|v['network'] == 'bitcoin'}.each do |v|
        expect(Bitcoin::MessageSign.verify_message(v['address'], v['signature'], v['message'])).to be true
        if v['compressed']
          expect(Bitcoin::MessageSign.verify_message(v['compressed']['address'], v['compressed']['signature'], v['message'])).to be true
        end
      end
    end
  end

  shared_examples "test invalid spec" do
    it do
      invalid['signature'].each do |v|
        expect{Bitcoin::MessageSign.verify_message('15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs', Base64.encode64(v['hex'].htb), '')}.
          to raise_error(ArgumentError, v['exception'])
      end
      invalid['verify'].each do |v|
        expect(Bitcoin::MessageSign.verify_message(v['address'], v['signature'], v['message'])).to be false
      end
    end
  end

  describe 'Test Vector' do
    context 'valid' do
      let(:valid) { fixtures['valid'] }
      it 'message hash generate hash.' do
        valid['magicHash'].each do |v|
          digest = Bitcoin::MessageSign.message_hash(v['message'], prefix: prefix(v['network']))
          expect(digest.bth).to eq(v['magicHash'])
        end
      end

      context 'using libsecp256ke', use_secp256k1: true do
        it_behaves_like "test valid spec", "secp256k1"
      end

      context 'pure ruby' do
        it_behaves_like "test valid spec", "pure ruby"
      end
    end

    let(:invalid) { fixtures['invalid'] }
    context 'invalid' do
      context 'raise error. using libsecp256k1', use_secp256k1: true do
        it_behaves_like "test invalid spec", "secp256k1"
      end

      context 'raise error.' do
        it_behaves_like "test invalid spec", "pure ruby"
      end
    end
  end

  describe 'Random data' do
    it 'generate same signature between ruby and libsecp256k1', use_secp256k1: true do
      Parallel.each(1..100) do
        key = Bitcoin::Secp256k1::Native.generate_key
        compressed = true
        digest = SecureRandom.random_bytes(32)
        sig1, rec1 = Bitcoin::Secp256k1::Native.sign_compact(digest, key.priv_key)
        sig2, rec2 = Bitcoin::Secp256k1::Ruby.sign_compact(digest, key.priv_key)
        expect(sig1).to eq(sig2)
        expect(rec1).to eq(rec2)
        rec = Bitcoin::Key::COMPACT_SIG_HEADER_BYTE + rec1 + (compressed ? 4 : 0)
        signature = [rec].pack('C') + ECDSA::Format::IntegerOctetString.encode(sig1.r, 32) +
          ECDSA::Format::IntegerOctetString.encode(sig1.s, 32)
        native_key = Bitcoin::Secp256k1::Native.recover_compact(digest, signature, rec1, compressed)
        ruby_key = Bitcoin::Secp256k1::Ruby.recover_compact(digest, signature, rec1, compressed)
        expect(key.pubkey).to eq(native_key.pubkey)
        expect(key.pubkey).to eq(ruby_key.pubkey)
      end
    end
  end

  describe "BIP322 Test Vector", network: :mainnet do
    it do
      # Message hashing
      digest1 = described_class.message_hash('', legacy: false )
      digest2 = described_class.message_hash('Hello World', legacy: false)
      expect(digest1.bth).to eq('c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1')
      expect(digest2.bth).to eq('f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a')

      # Message signing
      private_key = Bitcoin::Key.from_wif('L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k')
      addr = private_key.to_p2wpkh
      expect(addr).to eq("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l")
      sig1 = described_class.sign_message(
        private_key,
        '',
        format: described_class::FORMAT_SIMPLE,
        address: addr)
      expect(sig1).to eq('AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=')
      sig2 = described_class.sign_message(
        private_key,
        'Hello World',
        format: described_class::FORMAT_SIMPLE,
        address: addr)
      expect(sig2).to eq('AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=')

      # Transaction hash
      to_spend1 = described_class.to_spend_tx(digest1, addr)
      expect(to_spend1.txid).to eq('c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7')
      to_spend2 = described_class.to_spend_tx(digest2, addr)
      expect(to_spend2.txid).to eq('b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b')

      to_sign1 = described_class.to_sign_tx(digest1, addr)
      expect(to_sign1.txid).to eq('1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6')
      to_sign2 = described_class.to_sign_tx(digest2, addr)
      expect(to_sign2.txid).to eq('88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf')

      # Verify signature
      expect(described_class.verify_message(addr, sig1, '')).to be true
      expect(described_class.verify_message(addr, sig2, 'Hello World')).to be true
    end
  end

  def prefix(network)
    fixtures['networks'][network]
  end

  shared_examples "test bitcoin core spec" do
    it do
      message = 'Trust no one'
      private_key = 'd97f5108f11cda6eeebaaa420fef0726b1f898060b98489fa3098463c0032866'
      key = Bitcoin::Key.new(priv_key: private_key, key_type: Bitcoin::Key::TYPES[:compressed])
      expect(key.to_p2pkh).to eq('15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs')
      expect(Bitcoin::MessageSign.message_hash(message).bth).to eq('aa8215d723ecd2f14867eeb7e19f192be7bc15a2352a24b991d4f5870cbaf6e8')
      signature = Bitcoin::MessageSign.sign_message(key, message)
      expect(signature).to eq('IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk=')
      expect(Bitcoin::MessageSign.verify_message(key.to_p2pkh, signature, message)).to be true

      expect{Bitcoin::MessageSign.verify_message("invalid address",
                                                 "signature should be irrelevant",
                                                 "message too")}.to raise_error(ArgumentError, 'Invalid address.')
      expect{Bitcoin::MessageSign.verify_message("3B5fQsEXEaV8v6U3ejYc8XaKXAkyQj2MjV",
                                                 "signature should be irrelevant",
                                                 "message too")}.to raise_error(ArgumentError, 'Invalid signature')
      expect{Bitcoin::MessageSign.verify_message("1KqbBpLy5FARmTPD4VZnDDpYjkUvkr82Pm",
                                                 "invalid signature, not in base64 encoding",
                                                 "message should be irrelevant")}.to raise_error(ArgumentError, 'Invalid signature')
      expect(Bitcoin::MessageSign.verify_message("1KqbBpLy5FARmTPD4VZnDDpYjkUvkr82Pm",
                                                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                                 "message should be irrelevant")).to be false
      expect(Bitcoin::MessageSign.verify_message("15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs",
                                                 "IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk=",
                                                 "I never signed this")).to be false
      expect(Bitcoin::MessageSign.verify_message("15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs",
                                                 "IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk=",
                                                 "Trust no one")).to be true
      expect(Bitcoin::MessageSign.verify_message("11canuhp9X2NocwCq7xNrQYTmUgZAnLK3",
                                                 "IIcaIENoYW5jZWxsb3Igb24gYnJpbmsgb2Ygc2Vjb25kIGJhaWxvdXQgZm9yIGJhbmtzIAaHRtbCeDZINyavx14=",
                                                 "Trust me")).to be true
    end
  end

  describe 'sign_message in Bitcoin Core' do
    context 'using libsecp256k1', use_secp256k1: true do
      it_behaves_like "test bitcoin core spec", "secp256k1"
    end

    context 'pure ruby' do
      it_behaves_like "test bitcoin core spec", "pure ruby"
    end
  end
end
