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

    it 'should reject a truncated payload and data after the script' do
      [payload[0, 40], payload[0, 48], payload[0, 49], payload[0...-1]].each do |cut|
        expect { Bitcoin::Wallet::Utxo.parse_from_payload(cut) }.to raise_error(ArgumentError), cut.bytesize.to_s
      end
      expect { Bitcoin::Wallet::Utxo.parse_from_payload(payload + "\x00".b) }.to raise_error(ArgumentError, 'Utxo payload has data after the script.')
      expect(Bitcoin::Wallet::Utxo.parse_from_payload(nil)).to be_nil
    end
  end

  describe '#initialize' do
    let(:tx_hash) { "a6a712b092bd8a9606877c7a53edf0af8442706e1bd4970d3ca4b7106afea227" }
    let(:script_pubkey) { Bitcoin::Script.to_p2wpkh('00' * 20) }

    it 'should reject a value the serialization would change' do
      expect(Bitcoin::Wallet::Utxo.new(tx_hash, 0, 0, script_pubkey).block_height).to be_nil
      expect(Bitcoin::Wallet::Utxo.new(tx_hash, 2**32 - 1, 2**64 - 1, script_pubkey, 2**32 - 1).value).to eq(2**64 - 1)
      expect { Bitcoin::Wallet::Utxo.new(tx_hash, 0, 0.5, script_pubkey) }.to raise_error(ArgumentError, 'value must be an integer from 0 to 2**64 - 1.')
      expect { Bitcoin::Wallet::Utxo.new(tx_hash, 0, -1, script_pubkey) }.to raise_error(ArgumentError, 'value must be an integer from 0 to 2**64 - 1.')
      expect { Bitcoin::Wallet::Utxo.new(tx_hash, 0, 2**64, script_pubkey) }.to raise_error(ArgumentError, 'value must be an integer from 0 to 2**64 - 1.')
      expect { Bitcoin::Wallet::Utxo.new(tx_hash, 2**32, 1, script_pubkey) }.to raise_error(ArgumentError, 'index must be an integer from 0 to 2**32 - 1.')
      expect { Bitcoin::Wallet::Utxo.new(tx_hash, -1, 1, script_pubkey) }.to raise_error(ArgumentError, 'index must be an integer from 0 to 2**32 - 1.')
      expect { Bitcoin::Wallet::Utxo.new('abcd', 0, 1, script_pubkey) }.to raise_error(ArgumentError, 'tx_hash must be a 32 byte hash with hex format.')
      expect { Bitcoin::Wallet::Utxo.new(tx_hash, 0, 1, '0014' + '00' * 20) }.to raise_error(ArgumentError, 'script_pubkey must be a Bitcoin::Script.')
      expect { Bitcoin::Wallet::Utxo.new(tx_hash, 0, 1, script_pubkey, 0) }.to raise_error(ArgumentError, 'block_height must be nil or an integer from 1 to 2**32 - 1.')
      expect { Bitcoin::Wallet::Utxo.new(tx_hash, 0, 1, script_pubkey, 2**32) }.to raise_error(ArgumentError, 'block_height must be nil or an integer from 1 to 2**32 - 1.')
    end
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
