require 'spec_helper'

include Bitcoin::Opcodes

RSpec.describe Bitcoin::Taproot::SimpleBuilder, network: :mainnet, use_secp256k1: true do

  describe '#initialize' do
    it 'should generate object' do
      key = Bitcoin::Key.new(priv_key: '98d2f0b8dfcaa7b29933bc78e8d82cd9d7c7a18ddc128ce2bc9dd143804f36f4')
      expect{Bitcoin::Taproot::SimpleBuilder.new('')}.to raise_error(Bitcoin::Taproot::Error, 'Internal public key must be 32 bytes')
      expect{Bitcoin::Taproot::SimpleBuilder.new(key.pubkey)}.to raise_error(Bitcoin::Taproot::Error, 'Internal public key must be 32 bytes')
      expect{Bitcoin::Taproot::SimpleBuilder.new(key.xonly_pubkey)}.not_to raise_error
      expect{Bitcoin::Taproot::SimpleBuilder.new(key.xonly_pubkey, [key.xonly_pubkey])}.to raise_error(Bitcoin::Taproot::Error, 'leaf must be Bitcoin::Taproot::LeafNode object')
      expect{Bitcoin::Taproot::SimpleBuilder.new(key.xonly_pubkey, [Bitcoin::Taproot::LeafNode.new(Bitcoin::Script.to_p2pkh(key.hash160))])}.not_to raise_error
    end
  end

  describe 'add condition' do
    it 'should add condition' do
      key = Bitcoin::Key.new(priv_key: '98d2f0b8dfcaa7b29933bc78e8d82cd9d7c7a18ddc128ce2bc9dd143804f36f4')
      builder = Bitcoin::Taproot::SimpleBuilder.new(key.xonly_pubkey)
      expect(builder.branches.size).to eq(0)
      builder.add_leaf(Bitcoin::Taproot::LeafNode.new(Bitcoin::Script.to_p2pkh(key.hash160)))
      expect(builder.branches.size).to eq(1)
      expect(builder.branches.first.size).to eq(1)
      expect{builder.add_leaf(key)}.to raise_error(Bitcoin::Taproot::Error, 'leaf must be Bitcoin::Taproot::LeafNode object')
    end
  end

  describe '#build' do
    let(:internal_key) { '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' }
    context 'has no script' do
      it 'should generate P2TR script' do
        builder = Bitcoin::Taproot::SimpleBuilder.new(internal_key)
        expect(builder.build.to_addr).to eq('bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9')
      end
    end

    context 'hash scripts' do
      it 'should generate P2TR script' do
        # tree leaves tree.
        #       N0
        #    /     \
        #   N1      C
        #  /  \
        # A    B
        key1 = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
        key2 = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
        key3 = '31fe7061656bea2a36aa60a2f7ef940578049273746935d296426dc0afd86b68'
        script1 = Bitcoin::Taproot::LeafNode.new(Bitcoin::Script.new << key1 << OP_CHECKSIG)
        script2 = Bitcoin::Taproot::LeafNode.new(Bitcoin::Script.new << key2 << OP_CHECKSIG)
        script3 = Bitcoin::Taproot::LeafNode.new(Bitcoin::Script.new << key3 << OP_CHECKSIG)
        builder = Bitcoin::Taproot::SimpleBuilder.new(internal_key, [script1, script2, script3])
        expect(builder.build.to_addr).to eq('bc1pkysykpr4e9alyu7wthrtmp2km6sylrjlz83qzrsjkxhdaazyfrusyk2pwg')

        # four leaves tree.
        #       N0
        #    /     \
        #   N1      N2
        #  /  \    /  \
        # A    B  C    D
        key4 = 'a016430f275c30cb15f399aa807cc9bde6b2c4c80c84be3bb27912089c18e363'
        script4 = Bitcoin::Script.new << key4 << OP_CHECKSIG
        builder.add_leaf(Bitcoin::Taproot::LeafNode.new(script4))
        expect(builder.build.to_addr).to eq('bc1pwr9amrwnxplrxdealu7h9rnfxusrdu8266ec83jpch3khjys9t9scpnpv6')

        # five leaves tree.
        #           N0
        #        /     \
        #       N1      E
        #    /     \
        #   N2      N3
        #  /  \    /  \
        # A    B  C    D
        key5 = 'b256afd27b26b0db101fd4a3d99afdd876dd2aaa5be967198882476bf425c301'
        script5 = Bitcoin::Script.new << key5 << OP_CHECKSIG
        builder.add_leaf(Bitcoin::Taproot::LeafNode.new(script5))
        expect(builder.build.to_addr).to eq('bc1pmxmu5slfv0zm3dsju74djrhkhd75qwpwht688vn0kw5f9j4z855sdx8c39')

        # six leaves tree.
        #            N0
        #        /        \
        #       N1         N2
        #    /     \      /  \
        #   N3      N4   E    F
        #  /  \    /  \
        # A    B  C    D
        key6 = '0e5ba1cfed1fe76ff81558731b7279ed23ddd95ce0fd67adc94584e80abbe987'
        script6 = Bitcoin::Script.new << key6 << OP_CHECKSIG
        builder.add_leaf(Bitcoin::Taproot::LeafNode.new(script6))
        expect(builder.build.to_addr).to eq('bc1peyxqpa4c4uzg9jzt7q92c94sk7kmj2uzhh2phuv8q8tkjrw6y67qf0u6mu')
      end
    end
  end

  describe "Support for using P2TR", network: :signet, use_secp256k1: true do
    it 'should complete tx' do
      internal_key = Bitcoin::Key.new(priv_key: '98d2f0b8dfcaa7b29933bc78e8d82cd9d7c7a18ddc128ce2bc9dd143804f36f4')
      key1 = Bitcoin::Key.new(priv_key: 'fd0137b05e26f40f8900697b690e11b2eba8abbd0f53c421148a22646b15f96f')
      key2 = Bitcoin::Key.new(priv_key: '3b0ce9ef75031f5a1d6679f017fdd8d77460ecdcac1a24d482e1465e1768e22c')
      key3 = Bitcoin::Key.new(priv_key: 'df94bce0533b3ff0c6b8ca16d6d2ce08b01350792cb350146cfaba056d5e4bfa')
      leaf1 = Bitcoin::Taproot::LeafNode.new(Bitcoin::Script.new << key1.xonly_pubkey << OP_CHECKSIG)
      leaf2 = Bitcoin::Taproot::LeafNode.new(Bitcoin::Script.new << key2.xonly_pubkey << OP_CHECKSIG)
      leaf3 = Bitcoin::Taproot::LeafNode.new(Bitcoin::Script.new << key3.xonly_pubkey << OP_CHECKSIG)
      builder = Bitcoin::Taproot::SimpleBuilder.new(internal_key.xonly_pubkey, [leaf1, leaf2, leaf3])
      script_pubkey = builder.build

      # Key-Path
      tx = Bitcoin::Tx.new
      tx.in << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.from_txid('9b5dbbe79a8938b9527b0a5f12c9be695ca1dac4e4267529a228c380c0b232bd', 1))
      tx.out << Bitcoin::TxOut.new(value: 90_000, script_pubkey: script_pubkey)
      key = builder.tweak_private_key(internal_key) # derive private key for sign
      prevouts = [Bitcoin::TxOut.new(value: 100_000, script_pubkey: script_pubkey)]
      sighash = tx.sighash_for_input(0, sig_version: :taproot, prevouts: prevouts, hash_type: Bitcoin::SIGHASH_TYPE[:default])
      sig = key.sign(sighash, algo: :schnorr)
      expect(sig).to eq(Bitcoin::Secp256k1::Ruby.sign_data(sighash, key.priv_key, algo: :schnorr))

      tx.in[0].script_witness.stack << sig
      expect(tx.to_hex).to eq('01000000000101bd32b2c080c328a2297526e4c4daa15c69bec9125f0a7b52b938899ae7bb5d9b0100000000ffffffff01905f0100000000002251202f1943ee0bafaef1944d3ff65bcbeb5e216055d369938cdcfb95a6d2ab7b4fc501409cbba40f90595e0ea05484725eeeb3fcd421ea6b98189c5c92d30869d4093d2736f6f90310b44e6dc4f0c2b47c7326f76ba7f340f28b0370d5962ef17c9247c900000000')
      expect(tx.verify_input_sig(0, prevouts[0].script_pubkey, amount: prevouts[0].value, prevouts: prevouts)).to be true

      # Script-Path
      tx = Bitcoin::Tx.new
      tx.in << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.from_txid('3cad3075b2cd448fdae11a9d3bb60d9b71acf6a279df7933dd6c966f29e0469d', 1))
      tx.out << Bitcoin::TxOut.new(value: 90_000, script_pubkey: script_pubkey)
      prevouts = [Bitcoin::TxOut.new(value: 100_000, script_pubkey: script_pubkey)]
      opts = {leaf_hash: leaf2.leaf_hash} # script pathではleaf hashにもコミットするためオプションで渡す
      sighash = tx.sighash_for_input(0, sig_version: :tapscript, prevouts: prevouts, hash_type: Bitcoin::SIGHASH_TYPE[:default], opts: opts)
      sig = key2.sign(sighash, algo: :schnorr)
      expect(sig).to eq(Bitcoin::Secp256k1::Ruby.sign_data(sighash, key2.priv_key, algo: :schnorr))
      tx.in[0].script_witness.stack << sig # sig for script2
      tx.in[0].script_witness.stack << leaf2.script.to_payload
      tx.in[0].script_witness.stack << builder.control_block(leaf2).to_payload # path
      expect(tx.to_hex).to eq('010000000001019d46e0296f966cdd3379df79a2f6ac719b0db63b9d1ae1da8f44cdb27530ad3c0100000000ffffffff01905f0100000000002251202f1943ee0bafaef1944d3ff65bcbeb5e216055d369938cdcfb95a6d2ab7b4fc50340c581e4700d1049cf4c075083f97bedf4c6ceb7b112b9cd3489c9ff809f02d7eb5358fec9a2672fd6664b92f338cd7a441e8d07ab4a90ba1b4292d269755dd91422204582dc979ec028044d80e911fb992d37801163cec6082b9807746d450b8ef773ac61c09b1e61ad40f333999250340eebb2257c0214e69ab3125022c1df50f6f5d0ebe3e13ebd0cd00421ea7d47f0b9270bf5c0677545a749189b7bbc2eb41faeb23145e2884fd612cee77b7f30b9bfaba55a48fa5ee74534b6e37326e7684cd54911cf00000000')
      expect(tx.verify_input_sig(0, prevouts[0].script_pubkey, amount: prevouts[0].value, prevouts: prevouts)).to be true
      expect(builder.control_block(leaf3).to_hex).to eq('c09b1e61ad40f333999250340eebb2257c0214e69ab3125022c1df50f6f5d0ebe383b6bc9d4cf55443a73437982fb6f274bf10c1d9666e4a0ef98688799ebf0dcb')
    end
  end

  describe 'bip341_wallet_vectors.json' do
    it 'should calculate correct script pubkey.' do
      fixtures = fixture_file('bip341_wallet_vectors.json')
      # scriptPubkey
      fixtures['scriptPubKey'].each do |data|
        internal_pubkey = data['given']['internalPubkey']
        script_tree = data['given']['scriptTree']
        builder = Bitcoin::Taproot::SimpleBuilder.new(internal_pubkey)
        if script_tree
          if script_tree.is_a?(Array)
            script_tree.each do |s|
              if s.is_a?(Array)
                s.each_slice(2) do |s1, s2|
                  if s2.nil?
                    builder.add_leaf(parse_script(s1))
                  else
                    builder.add_branch(parse_script(s1), parse_script(s2))
                  end
                end
              else
                builder.add_leaf(parse_script(s))
              end
            end
          else
            builder.add_leaf(parse_script(script_tree))
          end
        end
        intermediary = data['intermediary']
        expect(builder.tweak_public_key.xonly_pubkey).to eq(intermediary['tweakedPubkey'])

        expected = data['expected']
        script_pubkey = builder.build
        expect(script_pubkey.to_hex).to eq(expected['scriptPubKey'])
        expect(script_pubkey.to_addr).to eq(expected['bip350Address'])
        if expected['scriptPathControlBlocks']
          builder.branches.flatten.each_with_index do |leaf, index|
            expect(builder.control_block(leaf).to_hex).to eq(expected['scriptPathControlBlocks'][index])
          end
        end
      end

      # keyPathSpending
      fixtures['keyPathSpending'].each do |data|
        tx = Bitcoin::Tx.parse_from_payload(data['given']['rawUnsignedTx'].htb)
        prevouts = data['given']['utxosSpent'].map do |utxo|
          script_pubkey = Bitcoin::Script.parse_from_payload(utxo['scriptPubKey'].htb)
          Bitcoin::TxOut.new(script_pubkey: script_pubkey, value: utxo['amountSats'])
        end
        data['inputSpending'].each do |spending|
          index = spending['given']['txinIndex']
          hash_type = spending['given']['hashType']

          internal_private_key = Bitcoin::Key.new(priv_key: spending['given']['internalPrivkey'])
          expect(internal_private_key.xonly_pubkey).to eq(spending['intermediary']['internalPubkey'])
          merkle_root = spending['given']['merkleRoot']
          expect(Bitcoin::Taproot.tweak(internal_private_key, merkle_root).bth).to eq(spending['intermediary']['tweak'])
          tweaked_key = Bitcoin::Taproot.tweak_private_key(internal_private_key, merkle_root)
          expect(tweaked_key.priv_key).to eq(spending['intermediary']['tweakedPrivkey'])

          # Calculate sighash
          sighash = tx.sighash_for_input(index, sig_version: :taproot, prevouts: prevouts, hash_type: hash_type)
          expect(sighash.bth).to eq(spending['intermediary']['sigHash'])
          # Generate signature (The test vector signature is created by setting aux_rand to 32-byte 0.)
          signature = tweaked_key.sign(sighash, true, ('00' * 32).htb, algo: :schnorr)
          signature += [hash_type].pack('C') unless hash_type == Bitcoin::SIGHASH_TYPE[:default]
          expect([signature.bth]).to eq(spending['expected']['witness'])
        end
      end
    end
  end

  def parse_script(script_json)
    Bitcoin::Taproot::LeafNode.new(
      Bitcoin::Script.parse_from_payload(script_json['script'].htb), script_json['leafVersion'])
  end

end