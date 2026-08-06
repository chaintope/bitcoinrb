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
