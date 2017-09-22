require 'spec_helper'

describe Bitcoin::Block do

  subject {
    payload = load_block('0000000000343e7e31a6233667fd6ed5288d60ed7e894ae5d53beb0dffc89170').htb
    Bitcoin::Message::Block.parse_from_payload(payload).to_block
  }

  describe 'calculate size' do
    it 'should be calculate.' do
      expect(subject.stripped_size).to eq(34647)
      expect(subject.size).to eq(34792)
      expect(subject.weight).to eq(138733)
    end
  end

  describe '#valid_merkle_root?' do
    context 'valid' do
      it 'should be true' do
        expect(subject.valid_merkle_root?).to be true
      end
    end

    context 'invalid' do
      it 'should be false' do
        block = subject
        coinbase_tx = block.transactions[0]
        coinbase_tx.inputs[0].script_sig = (coinbase_tx.inputs[0].script_sig << '00')
        expect(subject.valid_merkle_root?).to be false
      end
    end
  end

  describe '#valid_witness_commitment?' do
    context 'valid' do
      it 'should be true'do
        expect(subject.valid_witness_commitment?).to be true
      end
    end

    context 'unsupported reserved value' do
      it 'should be false' do
        subject.transactions[0].inputs[0].script_witness.stack[0] = '0000000000000000000000000000000000000000000000000000000000000001'.htb
        expect(subject.valid_witness_commitment?).to be false
      end
    end

    context 'change wtxid' do
      it 'should be false' do
        subject.transactions[1].inputs[0].script_witness.stack[0] = '0000000000000000000000000000000000000000000000000000000000000000'.htb
        expect(subject.valid_witness_commitment?).to be false
      end
    end
  end

  describe '#height' do
    context 'block version 2' do
      subject { # height is 21106. testnet first version 2 block.
        payload = load_block('0000000070b701a5b6a1b965f6a38e0472e70b2bb31b973e4638dec400877581').htb
        Bitcoin::Message::Block.parse_from_payload(payload).to_block
      }
      it 'return block height' do
        expect(subject.height).to eq(21106)
      end
    end

    context 'block versoin 1' do
      subject { # height is 21105. testnet last version 1 block.
        payload = load_block('000000009020a075cc7af813d46a1ef24eb2b0035e131937153146cc3711542a').htb
        Bitcoin::Message::Block.parse_from_payload(payload).to_block
      }
      it 'return nil' do
        expect(subject.height).to be nil
      end
    end
  end

end