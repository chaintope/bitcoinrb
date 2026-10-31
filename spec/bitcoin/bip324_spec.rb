require 'spec_helper'

RSpec.describe Bitcoin::BIP324 do

  let(:decode_vectors) { read_csv('bip324/ellswift_decode_test_vectors.csv') }
  let(:xswiftec_inv_vectors) { read_csv('bip324/xswiftec_inv_test_vectors.csv') }
  let(:packet_encoding_vectors) { read_csv('bip324/packet_encoding_test_vectors.csv') }

  shared_examples "test vector" do
    it do
      decode_vectors.each do |v|
        k = Bitcoin::BIP324::EllSwiftPubkey.new(v['ellswift'])
        expect(k.decode.xonly_pubkey).to eq(v['x'])
      end
    end
  end
  describe '#decode' do
    context 'native', use_secp256k1: true do
      it_behaves_like "test vector", "secp256k1"
    end

    context 'ruby' do
      it_behaves_like "test vector", "pure ruby"
    end
  end

  describe 'FSChaCha20' do
    # Vectors of Bitcoin Core's crypto_tests: the ciphertext of the first chunk after the key rotation.
    # They only match when the keystream left over from the old key is discarded at the rotation.
    [
      ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '00' * 32, 256,
       'a93df4ef03011f3db95f60d996e1785df5de38fc39bfcb663a47bb5561928349'],
      ['01', '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 5, 'ea'],
      ['e93fdb5c762804b9a706816aca31e35b11d2aa3080108ef46a5b1f1508819c0a',
       '8ec4c3ccdaea336bdeb245636970be01266509b33f3d2642504eaf412206207a', 4096,
       '8bfaa4eacff308fdb4a94a5ff25bd9d0c1f84b77f81239f67ff39d6e1ac280c9']
    ].each do |plaintext, key, interval, expected|
      it "should rotate the key after #{interval} chunks" do
        cipher = Bitcoin::BIP324::FSChaCha20.new(key.htb, interval)
        interval.times { cipher.encrypt(plaintext.htb) }
        expect(cipher.encrypt(plaintext.htb).bth).to eq(expected)
      end
    end
  end

  describe "xswiftec_inv" do
    it do
      xswiftec_inv_vectors.each do |v|
        8.times do |c|
          r = described_class.xswiftec_inv(v['x'], v['u'], c)
          if r.nil?
            expect(v["case#{c}_t"]).to be nil
          else
            expect(r).to eq(v["case#{c}_t"])
            expect(described_class.xswiftec(v['u'], r))
          end
        end
      end
    end
  end

  describe "xelligatorswift" do
    it 'should encode x, selecting the case from the 8 xswiftec_inv defines' do
      x = decode_vectors.first['x']
      # c is read as 3 bits, so a selector of 8 is out of range and silently repeats case 0,
      # which biases the encoding away from the uniform distribution BIP-324 relies on.
      bounds = []
      allow(SecureRandom).to receive(:random_number).and_wrap_original do |original, arg|
        bounds << arg
        original.call(arg)
      end
      ellswift = described_class.xelligatorswift(x)

      expect(ellswift.htb.bytesize).to eq(64)
      expect(described_class.xswiftec(ellswift[0...64], ellswift[64..-1])).to eq(x)
      expect(bounds.grep(Integer).select { |b| b <= 256 }.uniq).to eq([described_class::CASE_COUNT])
      expect(described_class::CASE_COUNT).to eq(8)
    end
  end

  shared_examples "test ellswift ecdh" do
    it do
      packet_encoding_vectors.each do |v|
        initiating = v['in_initiating'] == "1"
        our_priv = Bitcoin::Key.new(priv_key: v['in_priv_ours'])
        expect(our_priv.xonly_pubkey).to eq(v['mid_x_ours'])
        our_ell = Bitcoin::BIP324::EllSwiftPubkey.new(v['in_ellswift_ours'])
        expect(our_ell.decode.xonly_pubkey).to eq(v['mid_x_ours'])
        their_ell = Bitcoin::BIP324::EllSwiftPubkey.new(v['in_ellswift_theirs'])
        expect(their_ell.decode.xonly_pubkey).to eq(v['mid_x_theirs'])
        cipher = Bitcoin::BIP324::Cipher.new(our_priv, our_ell)
        cipher.setup(their_ell, initiating)
        shared_x = described_class.v2_ecdh(our_priv.priv_key, their_ell, our_ell, initiating)
        expect(shared_x).to eq(v['mid_shared_secret'])
        if initiating
          expect(cipher.send_l_cipher.key.bth).to eq(v['mid_initiator_l'])
          expect(cipher.send_p_cipher.key.bth).to eq(v['mid_initiator_p'])
          expect(cipher.recv_l_cipher.key.bth).to eq(v['mid_responder_l'])
          expect(cipher.recv_p_cipher.key.bth).to eq(v['mid_responder_p'])
        else
          expect(cipher.recv_l_cipher.key.bth).to eq(v['mid_initiator_l'])
          expect(cipher.recv_p_cipher.key.bth).to eq(v['mid_initiator_p'])
          expect(cipher.send_l_cipher.key.bth).to eq(v['mid_responder_l'])
          expect(cipher.send_p_cipher.key.bth).to eq(v['mid_responder_p'])
        end
        expect(cipher.send_garbage_terminator).to eq(v['mid_send_garbage_terminator'])
        expect(cipher.recv_garbage_terminator).to eq(v['mid_recv_garbage_terminator'])
        expect(cipher.session_id).to eq(v['out_session_id'])

        in_index = v['in_idx'].to_i
        dummies = in_index.times.map do
          cipher.encrypt("")
        end
        aad = v['in_aad'] ? v['in_aad'].htb : ''
        contents = v['in_contents'].htb * v['in_multiply'].to_i
        ignore = v['in_ignore'] == '1'
        ciphertext = cipher.encrypt(contents, aad: aad, ignore: ignore)
        if v['out_ciphertext']
          expect(ciphertext.bth).to eq(v['out_ciphertext'])
        end
        if v['out_ciphertext_endswith']
          expect(ciphertext.bth).to end_with(v['out_ciphertext_endswith'])
        end

        # Decrypt
        dec_cipher = Bitcoin::BIP324::Cipher.new(our_priv, our_ell)
        dec_cipher.setup(their_ell, initiating, true)
        expect(dec_cipher.session_id).to eq(v['out_session_id'])
        expect(dec_cipher.send_garbage_terminator).to eq(v['mid_send_garbage_terminator'])
        expect(dec_cipher.recv_garbage_terminator).to eq(v['mid_recv_garbage_terminator'])

        in_index.times do |i|
          dec_cipher.decrypt(dummies[i])
        end

        _, plaintext = dec_cipher.decrypt(ciphertext, aad: aad, ignore: ignore)
        expect(plaintext.bth).to eq(contents.bth)
      end
    end
  end

  describe "ellswift_xdh", network: :mainnet do
    context "native", use_secp256k1: true do
      it_behaves_like "test ellswift ecdh", "secp256k1"
    end

    context "ruby" do
      it_behaves_like "test ellswift ecdh", "pure ruby"
    end
  end
end
