require 'spec_helper'
include Bitcoin::Opcodes

describe Bitcoin::Multisig do
  describe '#to_multisig_script_sig' do
    let(:sig) {
      [
        '3045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf9868a0',
        '51e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d6335874ed',
        'fe086ee0a08fec'
      ].join.htb
    }
    let(:hash_type) { Bitcoin::SIGHASH_TYPE[:none] }
    subject { Bitcoin::Multisig.to_multisig_script_sig(sig, sig, hash_type) }
    it "should generate multisig script sig" do
      expected_script = [
        '00483045022062437a8f60651cd968137355775fa8bdb83d4ca717fdbc08bf98',
        '68a051e0542f022100f5cd626c15ef0de0803ddf299e8895743e7ff484d63358',
        '74edfe086ee0a08fec02483045022062437a8f60651cd968137355775fa8bdb8',
        '3d4ca717fdbc08bf9868a051e0542f022100f5cd626c15ef0de0803ddf299e88',
        '95743e7ff484d6335874edfe086ee0a08fec02'
      ].join.htb
      expect(subject).to eq expected_script
    end
  end

  describe '#sort_p2sh_multisig_signatures' do
    let(:tx) do
      Bitcoin::Tx.new.tap do |tx|
        out_point = Bitcoin::OutPoint.new("txid", 0)
        tx.inputs << Bitcoin::TxIn.new(out_point: out_point)
        tx.outputs << Bitcoin::TxOut.new(value: 10_000_000, script_pubkey: p2sh[0])
      end
    end
    let(:p2sh) { Bitcoin::Script.to_p2sh_multisig_script(m, keys.map(&:pubkey)) }
    let(:keys) { 3.times.map { Bitcoin::Key.generate } }
    let(:sig_hash) { tx.sighash_for_input(0, p2sh[1]) }

    subject { tx.verify_input_sig(0, p2sh[0]) }

    context "3 of 3" do
      let(:m) { 3 }
      it do
        # add sigs in all possible orders, sort them, and see if they are valid
        [0, 1, 2].permutation(m) do |order|
          script_sig = Bitcoin::Multisig.to_p2sh_multisig_script_sig(p2sh[1].to_payload, order.map {|i| keys[i].sign(sig_hash)})
          script_sig = Bitcoin::Multisig.sort_p2sh_multisig_signatures(script_sig, sig_hash)
          tx.inputs[0].script_sig = Bitcoin::Script.parse_from_payload(script_sig)
          expect(subject).to be_truthy
        end
      end
    end

    context "2 of 3" do
      let(:m) { 2 }
      it do
        # add sigs in all possible orders, sort them, and see if they are valid
        [0, 1, 2].permutation(m) do |order|
          script_sig = Bitcoin::Multisig.to_p2sh_multisig_script_sig(p2sh[1].to_payload, order.map {|i| keys[i].sign(sig_hash)})
          script_sig = Bitcoin::Multisig.sort_p2sh_multisig_signatures(script_sig, sig_hash)
          tx.inputs[0].script_sig = Bitcoin::Script.parse_from_payload(script_sig)
          expect(subject).to be_truthy
        end
      end
    end
  end
end
