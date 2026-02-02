require 'spec_helper'
RSpec.describe Bitcoin::Message::SendTxRcncl, network: :mainnet do
  let(:pkt) { 'f9beb4d973656e64747872636e636c000c000000c9e5633701000000a1b2c3d4e5f60718' }

  it 'should generate sendtxrcncl message' do
    send_tx_rcncl = Bitcoin::Message::Base.from_pkt(pkt.htb)
    expect(send_tx_rcncl).to be_a(Bitcoin::Message::SendTxRcncl)
    expect(send_tx_rcncl.version).to eq(1)
    expect(send_tx_rcncl.salt).to eq(['a1b2c3d4e5f60718'].pack("H*").reverse.bti)

    expect(send_tx_rcncl.to_pkt.bth).to eq(pkt)
  end

end