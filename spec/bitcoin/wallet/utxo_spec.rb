require 'spec_helper'

describe 'Bitcoin::Wallet::Utxo' do
  describe '.parse_from_payload' do
    subject { Bitcoin::Wallet::Utxo.parse_from_payload(payload) }

    let(:payload) { "a6a712b092bd8a9606877c7a53edf0af8442706e1bd4970d3ca4b7106afea2270100000002000000ffffffffffffffff1976a914f1566ac8cd7f2a0ad04611a02ebbda7da978829e88ac".htb }

    it { expect(subject.tx_hash).to eq "a6a712b092bd8a9606877c7a53edf0af8442706e1bd4970d3ca4b7106afea227" }
    it { expect(subject.index).to eq 1 }
    it { expect(subject.value).to eq 18_446_744_073_709_551_615 }
    it { expect(subject.script_pubkey).to eq Bitcoin::Script.parse_from_payload("76a914f1566ac8cd7f2a0ad04611a02ebbda7da978829e88ac".htb) }
    it { expect(subject.block_height).to eq 2 }
  end

  describe '#to_payload' do
    subject { utxo.to_payload.bth }

    let(:utxo) { Bitcoin::Wallet::Utxo.new(tx_hash, index, value, script_pubkey, block_height) }
    let(:tx_hash) { "a6a712b092bd8a9606877c7a53edf0af8442706e1bd4970d3ca4b7106afea227" }
    let(:index) { 1 }
    let(:value) { 18_446_744_073_709_551_615 }
    let(:script_pubkey) { Bitcoin::Script.parse_from_payload("76a914f1566ac8cd7f2a0ad04611a02ebbda7da978829e88ac".htb) }
    let(:block_height) { 2 }

    it { is_expected.to eq "a6a712b092bd8a9606877c7a53edf0af8442706e1bd4970d3ca4b7106afea2270100000002000000ffffffffffffffff1976a914f1566ac8cd7f2a0ad04611a02ebbda7da978829e88ac" }
  end
end
