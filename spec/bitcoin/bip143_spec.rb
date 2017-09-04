require 'spec_helper'

describe 'BIP 143 spec', use_secp256k1: true do

  # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Example

  describe 'Native P2WPKPH' do
    it 'verify ecdsa signature' do
      tx = Bitcoin::Tx.parse_from_payload('0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000'.htb)

      script_pubkey0 = Bitcoin::Script.parse_from_payload('2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac'.htb)
      sig_hash0 = tx.sighash_for_input(input_index: 0, output_script: script_pubkey0)

      key0 = Bitcoin::Key.new(priv_key: 'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866')
      sig0 = key0.sign(sig_hash0) + [Bitcoin::Script::SIGHASH_TYPE[:all]].pack('C')

      tx.inputs[0].script_sig = Bitcoin::Script.parse_from_payload(Bitcoin::Script.pack_pushdata(sig0))

      script_pubkey1 = Bitcoin::Script.parse_from_payload('00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'.htb)
      sig_hash1 = tx.sighash_for_input(input_index: 1, output_script: script_pubkey1,
                                       amount: 600000000, sig_version: Bitcoin::ScriptInterpreter::SIG_VERSION[:witness_v0])
      key1 = Bitcoin::Key.new(priv_key: '619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9')
      sig1 = key1.sign(sig_hash1) + [Bitcoin::Script::SIGHASH_TYPE[:all]].pack('C')

      tx.inputs[1].script_witness.stack << sig1
      tx.inputs[1].script_witness.stack << '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357'.htb

      expect(tx.to_payload.bth).to eq('01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000')
    end
  end

  describe 'Native P2WSH' do
    it 'verify ecdsa signature' do
      witness_script = Bitcoin::Script.parse_from_payload('21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac'.htb)

      tx = Bitcoin::Tx.parse_from_payload('0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000'.htb)

      script_pubkey0 = Bitcoin::Script.parse_from_payload('21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac'.htb)
      sig_hash0 = tx.sighash_for_input(input_index: 0, output_script: script_pubkey0)
      key0 = Bitcoin::Key.new(priv_key: 'b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c')
      sig0 = key0.sign(sig_hash0) + [Bitcoin::Script::SIGHASH_TYPE[:all]].pack('C')
      tx.inputs[0].script_sig = Bitcoin::Script.parse_from_payload(Bitcoin::Script.pack_pushdata(sig0))

      sig_hash1 = tx.sighash_for_input(input_index: 1, output_script: witness_script, amount: 4900000000,
                                       hash_type: Bitcoin::Script::SIGHASH_TYPE[:single], sig_version: Bitcoin::ScriptInterpreter::SIG_VERSION[:witness_v0])
      key1 = Bitcoin::Key.new(priv_key: '8e02b539b1500aa7c81cf3fed177448a546f19d2be416c0c61ff28e577d8d0cd')
      sig1 = key1.sign(sig_hash1) + [Bitcoin::Script::SIGHASH_TYPE[:single]].pack('C')

      sig_hash2 = tx.sighash_for_input(input_index: 1, output_script: witness_script, amount: 4900000000, skip_separator_index: 1,
                                       hash_type: Bitcoin::Script::SIGHASH_TYPE[:single], sig_version: Bitcoin::ScriptInterpreter::SIG_VERSION[:witness_v0])
      key2 = Bitcoin::Key.new(priv_key: '86bf2ed75935a0cbef03b89d72034bb4c189d381037a5ac121a70016db8896ec')
      sig2 = key2.sign(sig_hash2) + [Bitcoin::Script::SIGHASH_TYPE[:single]].pack('C')

      tx.inputs[1].script_witness.stack << sig2
      tx.inputs[1].script_witness.stack << sig1
      tx.inputs[1].script_witness.stack << witness_script.to_payload

      expect(tx.to_payload.bth).to eq('01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000')
    end
  end

end