require 'spec_helper'

RSpec.describe Bitcoin::MessageSign, network: :mainnet do

  # bitcoinjs-lib fixtures.
  let(:fixtures) { fixture_file('message_signs.json') }

  # BIP322 test vector
  let(:basic) { fixture_file('bip322/basic-test-vectors.json') }
  let(:generated) { fixture_file('bip322/generated-test-vectors.json') }

  describe "BIP-322 basic test vectors" do
    it do
      basic['tx_hashes'].each do |tx_hash|
        digest = described_class.message_hash(tx_hash['message'], legacy: false)
        expect(digest.bth).to eq(tx_hash['message_hash'])

        spend_tx = described_class.to_spend_tx(digest, tx_hash['address'])
        expect(spend_tx.txid).to eq(tx_hash['to_spend_tx_hash'])
        to_sign_tx = described_class.to_sign_tx(digest, tx_hash['address'])
        expect(to_sign_tx.txid).to eq(tx_hash['to_sign_tx_hash'])
      end
      basic['simple'].each do |simple|
        if simple['private_keys'].length == 1
          private_key = Bitcoin::Key.from_wif(simple['private_keys'].first)
          sig = described_class.sign_message(private_key, simple['message'], format: :simple, address: simple['address'])
          if Bitcoin::Script.parse_from_addr(simple['address']).p2tr?
            expect(described_class.verify_message(simple['address'], sig, simple['message'])).to be true
          else
            strip = ->(s) { s.sub(/\A(smp|ful|pof)/, '') }
            expect(strip.call(sig)).to eq(strip.call(simple['bip322_signatures'].first))
          end
        end
        simple['bip322_signatures'].each do |sig|
          expect(described_class.verify_message(simple['address'], sig, simple['message'])).to be true
        end
      end
      basic['error'].each do |error|
        if error['error_substr'] == 'invalid signature'
          expect(
            described_class.verify_message(error['address'], error['signature'], error['message'])
          ).to be false
        else
          expect {
            described_class.verify_message(error['address'], error['signature'], error['message'])
          }.to raise_error(ArgumentError)
        end
      end
    end
  end

  describe "BIP-322 generated test vectors" do
    it do
      # Simple
      generated['simple'].each do |simple|
        simple['bip322_signatures'].each do |sig|
          expect(described_class.verify_message(simple['address'], sig, simple['message'])).to be true
        end
      end
      # Full
      generated['full'].each do |full|
        full['bip322_signatures'].each do |sig|
          expect(described_class.verify_message(full['address'], sig, full['message'])).to be true
        end
      end
      # Error
      generated['error'].each do |error|
        if error['error_substr'] == 'invalid signature'
          expect(
            described_class.verify_message(error['address'], error['signature'], error['message'])
          ).to be false
        else
          expect {
            described_class.verify_message(error['address'], error['signature'], error['message'])
          }.to raise_error(ArgumentError)
        end
      end
    end
  end

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
        native_key = Bitcoin::Secp256k1::Native.recover_compact(digest, signature, compressed)
        ruby_key = Bitcoin::Secp256k1::Ruby.recover_compact(digest, signature, compressed)
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
      expect(sig1).to eq('smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=')
      sig1_full = described_class.sign_message(
        private_key,
        '',
        format: described_class::FORMAT_FULL,
        address: addr)
      sig2 = described_class.sign_message(
        private_key,
        'Hello World',
        format: described_class::FORMAT_SIMPLE,
        address: addr)
      expect(sig2).to eq('smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=')

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
      expect(described_class.verify_message(addr, sig2, 'Hello World2')).to be false
      expect(described_class.verify_message(addr, sig1_full, '')).to be true
      expect(described_class.verify_message(addr, sig1_full, 'Hello')).to be false
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

  describe '#verify_message with a signature forged by an unrelated key' do
    # The negative BIP-322 vectors reject a wrong signer by replaying the signature of another
    # address, and to_spend commits to the address, so those fail on the sighash before the key
    # is ever compared to the address. These build a signature which is valid for the address's
    # own sighash, so only the binding between the key and the address rejects it. That binding
    # is what GHSA-5chw-87w3-j9cv was missing, and no test vector covers it.
    let(:victim) { Bitcoin::Key.from_wif('L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k') }
    let(:attacker) { Bitcoin::Key.from_wif('L4DksdGZ4KQJfcLHD5Dv25fu8Rxyv7hHi2RjZR4TYzr8c6h9VNrp') }
    let(:message) { 'Hello World' }

    # Sign the to_sign tx of +address+ with +key+, whichever key +address+ actually commits to.
    # @return [Array] the simple and the full variant of the signature.
    def forge(address, key, script_code: nil, tail: nil, redeem: nil)
      digest = described_class.message_hash(message, legacy: false)
      tx = described_class.to_sign_tx(digest, address)
      spk = Bitcoin::Script.parse_from_addr(address)
      prev_out = Bitcoin::TxOut.new(script_pubkey: spk, value: 0)
      tx.in[0].script_sig = Bitcoin::Script.new << redeem.to_payload if redeem
      if spk.p2tr?
        sighash = tx.sighash_for_input(0, spk, sig_version: :taproot, prevouts: [prev_out],
                                       hash_type: Bitcoin::SIGHASH_TYPE[:default])
        tweaked = Bitcoin::Taproot.tweak_private_key(key, '')
        tx.in[0].script_witness.stack << tweaked.sign(sighash, algo: :schnorr)
      else
        sighash = tx.sighash_for_input(0, script_code || spk, sig_version: :witness_v0,
                                       amount: 0, prevouts: [prev_out])
        tx.in[0].script_witness.stack << (key.sign(sighash) + [Bitcoin::SIGHASH_TYPE[:all]].pack('C'))
        tx.in[0].script_witness.stack << tail
      end
      [described_class::SIGNATURE_PREFIX_SIMPLE + Base64.strict_encode64(tx.in[0].script_witness.to_payload),
       described_class::SIGNATURE_PREFIX_FULL + Base64.strict_encode64(tx.to_payload)]
    end

    def witness_of(sig)
      Bitcoin::ScriptWitness.parse_from_payload(Base64.strict_decode64(sig[3..]))
    end

    it 'rejects a P2WPKH signature made by another key' do
      addr = victim.to_p2wpkh
      legit = forge(addr, victim, tail: victim.pubkey.htb)
      forged = forge(addr, attacker, tail: attacker.pubkey.htb)
      # The signature itself is valid, only hash160 of the witness key differs from the address.
      expect(witness_of(forged.first).stack.last.bth).to eq(attacker.pubkey)
      expect(attacker.hash160).not_to eq(victim.hash160)
      legit.zip(forged).each do |ok, ng|
        expect(described_class.verify_message(addr, ok, message)).to be true
        expect(described_class.verify_message(addr, ng, message)).to be false
      end
    end

    it 'rejects a P2SH-P2WPKH signature made by another key' do
      # The redeem script stays the victim's so the P2SH hash still matches, and only the key
      # in the witness is the attacker's. Simple is not defined for P2SH, so full only.
      addr = victim.to_nested_p2wpkh
      redeem = Bitcoin::Script.to_p2wpkh(victim.hash160)
      legit = forge(addr, victim, script_code: redeem, tail: victim.pubkey.htb, redeem: redeem)
      forged = forge(addr, attacker, script_code: redeem, tail: attacker.pubkey.htb, redeem: redeem)
      expect(described_class.verify_message(addr, legit.last, message)).to be true
      expect(described_class.verify_message(addr, forged.last, message)).to be false
    end

    it 'rejects a P2WSH signature made by another key' do
      victim_script = Bitcoin::Script.new << victim.pubkey << Bitcoin::Opcodes::OP_CHECKSIG
      attacker_script = Bitcoin::Script.new << attacker.pubkey << Bitcoin::Opcodes::OP_CHECKSIG
      addr = Bitcoin::Script.to_p2wsh(victim_script).to_addr
      legit = forge(addr, victim, script_code: victim_script, tail: victim_script.to_payload)
      # The attacker's own witness script does not hash to the address.
      forged = forge(addr, attacker, script_code: attacker_script, tail: attacker_script.to_payload)
      # The victim's witness script hashes to the address but commits to the victim's key.
      substituted = forge(addr, attacker, script_code: victim_script, tail: victim_script.to_payload)
      legit.zip(forged, substituted).each do |ok, ng, ng2|
        expect(described_class.verify_message(addr, ok, message)).to be true
        expect(described_class.verify_message(addr, ng, message)).to be false
        expect(described_class.verify_message(addr, ng2, message)).to be false
      end
    end

    it 'rejects a P2TR signature made by another key' do
      addr = victim.to_p2tr(as_internal: true)
      legit = forge(addr, victim)
      forged = forge(addr, attacker)
      expect(witness_of(forged.first).stack.first.bytesize).to eq(64)
      legit.zip(forged).each do |ok, ng|
        expect(described_class.verify_message(addr, ok, message)).to be true
        expect(described_class.verify_message(addr, ng, message)).to be false
      end
    end

    it 'rejects a legacy signature made by another key' do
      addr = victim.to_p2pkh
      expect(described_class.verify_message(
        addr, described_class.sign_message(victim, message), message)).to be true
      expect(described_class.verify_message(
        addr, described_class.sign_message(attacker, message), message)).to be false
    end
  end

  describe '#sign_message with a key the address does not commit to' do
    # Signing with such a key used to return a signature which verifies against no one,
    # and BIP-322 carries nothing that reports it.
    let(:key) { Bitcoin::Key.from_wif('L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k') }
    let(:other) { Bitcoin::Key.from_wif('L4DksdGZ4KQJfcLHD5Dv25fu8Rxyv7hHi2RjZR4TYzr8c6h9VNrp') }

    it 'raises for a P2WPKH address of another key' do
      expect(described_class.sign_message(
        key, 'Hello World', format: :simple, address: key.to_p2wpkh)).to be_a(String)
      expect {
        described_class.sign_message(key, 'Hello World', format: :simple, address: other.to_p2wpkh)
      }.to raise_error(ArgumentError, /Key does not correspond to/)
    end

    it 'raises for a P2TR address which is not the tweaked output key' do
      expect(described_class.sign_message(
        key, 'Hello World', format: :simple, address: key.to_p2tr(as_internal: true))).to be_a(String)
      # +to_p2tr+ without +as_internal+ is the untweaked key, so it is not this key's address.
      expect {
        described_class.sign_message(key, 'Hello World', format: :simple, address: key.to_p2tr)
      }.to raise_error(ArgumentError, /Key does not correspond to/)
      expect {
        described_class.sign_message(
          key, 'Hello World', format: :simple, address: other.to_p2tr(as_internal: true))
      }.to raise_error(ArgumentError, /Key does not correspond to/)
    end

    it 'raises for a P2WSH address' do
      # A P2WSH address commits to a witness script, which cannot be derived from a key alone.
      script = Bitcoin::Script.new << key.pubkey << Bitcoin::Opcodes::OP_CHECKSIG
      addr = Bitcoin::Script.to_p2wsh(script).to_addr
      expect {
        described_class.sign_message(key, 'Hello World', format: :simple, address: addr)
      }.to raise_error(ArgumentError, /not supported/)
    end
  end
end
