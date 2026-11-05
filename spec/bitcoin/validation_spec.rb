require 'spec_helper'

describe Bitcoin::Validation do

  let(:validation) { Bitcoin::Validation.new }
  let(:state) { Bitcoin::ValidationState.new }
  let(:block) do
    payload = load_block('0000000000343e7e31a6233667fd6ed5288d60ed7e894ae5d53beb0dffc89170').htb
    Bitcoin::Message::Block.parse_from_payload(payload).to_block
  end

  def spending_tx(*out_points)
    tx = Bitcoin::Tx.new
    out_points.each { |out_point| tx.in << Bitcoin::TxIn.new(out_point: out_point) }
    tx.out << Bitcoin::TxOut.new(value: 1, script_pubkey: Bitcoin::Script.to_p2wpkh('00' * 20))
    tx
  end

  describe '#check_tx' do
    it 'should set the state invalid when the check fails' do
      expect(validation.check_tx(Bitcoin::Tx.new, state)).to be false
      expect(state.mode).to eq(Bitcoin::ValidationState::MODE[:invalid])
      expect(state.mode).not_to be_nil
      expect(state.invalid?).to be true
      expect(state.valid?).to be false
      expect(state.reject_reason).to eq('bad-txns-vin-empty')
    end

    it 'should reject only the null prevout, which has a zero hash and index 0xffffffff' do
      zero_hash = Bitcoin::OutPoint::COINBASE_HASH
      other = Bitcoin::OutPoint.new('11' * 32, 0)
      expect(validation.check_tx(spending_tx(Bitcoin::OutPoint.new(zero_hash, 0), other), state)).to be true
      expect(state.valid?).to be true
      [Bitcoin::OutPoint.create_coinbase_outpoint, Bitcoin::OutPoint.new(zero_hash)].each do |null|
        state = Bitcoin::ValidationState.new
        expect(validation.check_tx(spending_tx(null, other), state)).to be false
        expect(state.reject_reason).to eq('bad-txns-prevout-null')
      end
    end

    it 'should not see an index which does not fit in 4 bytes as another index' do
      tx = spending_tx(Bitcoin::OutPoint.new('11' * 32, 2**32), Bitcoin::OutPoint.new('11' * 32, 0))
      expect { validation.check_tx(tx, state) }.to raise_error(ArgumentError, 'index must be an integer from 0 to 0xffffffff.')
    end
  end

  describe '#check_block_header' do
    it 'should check the proof of work' do
      expect(validation.check_block_header(block.header, state)).to be true
      header = Bitcoin::BlockHeader.parse_from_payload(block.header.to_payload)
      header.nonce += 1
      expect(validation.check_block_header(header, state)).to be false
      expect(state.reject_reason).to eq('high-hash')
      expect(state.n_dos).to eq(50)
    end
  end

  describe '#check_block' do
    it 'should accept a valid block' do
      expect(validation.check_block(block, state)).to be true
      expect(state.valid?).to be true
    end

    it 'should reject a block with a wrong merkle root' do
      block.transactions[1], block.transactions[2] = block.transactions[2], block.transactions[1]
      expect(validation.check_block(block, state)).to be false
      expect(state.reject_reason).to eq('bad-txnmrklroot')
      expect(state.corruption_possible).to be true
    end

    it 'should reject a block whose tx list is mutated (CVE-2012-2459)' do
      allow(block).to receive(:calculate_merkle_root).and_return(block.header.merkle_root)
      allow(block).to receive(:merkle_root_mutated?).and_return(true)
      expect(validation.check_block(block, state)).to be false
      expect(state.reject_reason).to eq('bad-txns-duplicate')
    end

    it 'should reject a block without any tx' do
      empty = Bitcoin::Block.new(block.header, [])
      expect(validation.check_block(empty, state)).to be false
      expect(state.reject_reason).to eq('bad-blk-length')
    end

    it 'should reject a block whose first tx is not the only coinbase' do
      txs = block.transactions
      allow(block).to receive(:calculate_merkle_root).and_return(block.header.merkle_root)
      block.transactions = txs[1..] + [txs[0]]
      expect(validation.check_block(block, state)).to be false
      expect(state.reject_reason).to eq('bad-cb-missing')
      state = Bitcoin::ValidationState.new
      block.transactions = [txs[0], txs[0]]
      allow(block).to receive(:merkle_root_mutated?).and_return(false)
      expect(validation.check_block(block, state)).to be false
      expect(state.reject_reason).to eq('bad-cb-multiple')
    end

    it 'should reject a block with an invalid tx' do
      allow(block).to receive(:calculate_merkle_root).and_return(block.header.merkle_root)
      block.transactions[1].out.clear
      expect(validation.check_block(block, state)).to be false
      expect(state.reject_reason).to eq('bad-txns-vout-empty')
    end

    it 'should count a CHECKMULTISIG as 20 legacy sigops' do
      allow(block).to receive(:calculate_merkle_root).and_return(block.header.merkle_root)
      multisig = Bitcoin::Script.new << Bitcoin::Opcodes::OP_CHECKMULTISIG
      checksig = Bitcoin::Script.new << Bitcoin::Opcodes::OP_CHECKSIG
      tx = block.transactions[1]
      # Fill the block up to the limit of 80_000 / 4 legacy sigops.
      count = block.transactions.sum { |t| validation.send(:legacy_sigop_count, t) }
      limit = Bitcoin::MAX_BLOCK_SIGOPS_COST / Bitcoin::WITNESS_SCALE_FACTOR
      ((limit - count) / 20).times { tx.out << Bitcoin::TxOut.new(value: 0, script_pubkey: multisig) }
      ((limit - count) % 20).times { tx.out << Bitcoin::TxOut.new(value: 0, script_pubkey: checksig) }
      expect(block.transactions.sum { |t| validation.send(:legacy_sigop_count, t) }).to eq(limit)
      expect(validation.check_block(block, state)).to be true
      tx.out << Bitcoin::TxOut.new(value: 0, script_pubkey: checksig)
      expect(validation.check_block(block, state)).to be false
      expect(state.reject_reason).to eq('bad-blk-sigops')
    end
  end

end
