require 'spec_helper'

RSpec.describe Bitcoin::TxChecker do

  describe '#check_schnorr_sig' do
    let(:tx) do
      tx = Bitcoin::Tx.new
      tx.in << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.new('11' * 32, 0))
      tx.out << Bitcoin::TxOut.new(value: 1000, script_pubkey: Bitcoin::Script.parse_from_payload('51'.htb))
      tx
    end
    let(:key) { Bitcoin::Key.generate }
    let(:prevout) { Bitcoin::TxOut.new(value: 2000, script_pubkey: Bitcoin::Script.new << Bitcoin::Opcodes::OP_1 << key.xonly_pubkey) }
    let(:checker) { described_class.new(tx: tx, input_index: 0, prevouts: [prevout]) }
    let(:sig) do
      sighash = tx.sighash_for_input(0, hash_type: Bitcoin::SIGHASH_TYPE[:default], sig_version: :taproot, prevouts: [prevout])
      key.sign(sighash, algo: :schnorr).bth
    end

    it 'should verify a signature by a key on the curve' do
      expect(checker.check_schnorr_sig(sig, key.xonly_pubkey, :taproot)).to be true
      expect(checker.has_error?).to be false
    end

    it 'should fail with SCRIPT_ERR_SCHNORR_SIG for a public key which is not on the curve' do
      expect(checker.check_schnorr_sig(sig, '00' * 32, :taproot)).to be false
      expect(checker.error_code).to eq(Bitcoin::SCRIPT_ERR_SCHNORR_SIG)
    end

    it 'should fail with SCRIPT_ERR_SCHNORR_SIG_HASHTYPE for SIGHASH_SINGLE without a corresponding output' do
      tx.in << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.new('22' * 32, 0))
      checker = described_class.new(tx: tx, input_index: 1, prevouts: [prevout, prevout])
      expect(checker.check_schnorr_sig('00' * 64 + '03', key.xonly_pubkey, :taproot)).to be false
      expect(checker.error_code).to eq(Bitcoin::SCRIPT_ERR_SCHNORR_SIG_HASHTYPE)
    end
  end

end
