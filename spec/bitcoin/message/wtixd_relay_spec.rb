require 'spec_helper'
RSpec.describe Bitcoin::Message::WTXIDRelay, network: :mainnet do

  it 'should generate wtxid message' do
    wtxid_relay = Bitcoin::Message::WTXIDRelay.new
    expect(wtxid_relay.to_pkt.bth).to eq('f9beb4d9777478696472656c61790000000000005df6e0e2')

    wtxid_relay = Bitcoin::Message::Base.from_pkt('f9beb4d9777478696472656c61790000000000005df6e0e2'.htb)
    expect(wtxid_relay).to be_a(Bitcoin::Message::WTXIDRelay)
  end

end