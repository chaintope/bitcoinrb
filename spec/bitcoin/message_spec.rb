require 'spec_helper'

RSpec.describe Bitcoin::Message do

  describe '#decode' do
    it 'generate message object corresponding to the command.' do
      ver = Bitcoin::Message.decode('version', '721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
      expect(ver).to be_a(Bitcoin::Message::Version)
      expect(ver.to_hex).to eq('721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')

      ack = Bitcoin::Message.decode('verack')
      expect(ack).to be_a(Bitcoin::Message::VerAck)
    end

    it 'generate message object for getblocks, filterload, filteradd, filterclear, getblocktxn and blocktxn.' do
      get_blocks = Bitcoin::Message::GetBlocks.new(70015, ['d18af7986e37cce50bd1840a4355b76c3127847538f598ca3c11050000000000'])
      expect(Bitcoin::Message.decode('getblocks', get_blocks.to_payload.bth)).to be_a(Bitcoin::Message::GetBlocks)

      filter_load = Bitcoin::Message::FilterLoad.new(Bitcoin::BloomFilter.new([0xb5, 0x0f], 11, 0))
      expect(Bitcoin::Message.decode('filterload', filter_load.to_payload.bth)).to be_a(Bitcoin::Message::FilterLoad)

      filter_add = Bitcoin::Message::FilterAdd.new('fdacf9b3eb077412e7a968d2e4f11b9a9dee312d666187ed77ee7d26af16cb0b')
      expect(Bitcoin::Message.decode('filteradd', filter_add.to_payload.bth)).to be_a(Bitcoin::Message::FilterAdd)

      expect(Bitcoin::Message.decode('filterclear')).to be_a(Bitcoin::Message::FilterClear)

      request = Bitcoin::Message::BlockTransactionRequest.new('9846a12e5eef1a4ba441233d76d3bcafb0bc4d86821dbb023971a91e839bf0f5', [1, 2])
      get_block_txn = Bitcoin::Message::GetBlockTxn.new(request)
      expect(Bitcoin::Message.decode('getblocktxn', get_block_txn.to_payload.bth)).to be_a(Bitcoin::Message::GetBlockTxn)

      transactions = Bitcoin::Message::BlockTransactions.new('9846a12e5eef1a4ba441233d76d3bcafb0bc4d86821dbb023971a91e839bf0f5', [])
      block_txn = Bitcoin::Message::BlockTxn.new(transactions)
      expect(Bitcoin::Message.decode('blocktxn', block_txn.to_payload.bth)).to be_a(Bitcoin::Message::BlockTxn)
    end
  end

end