require 'spec_helper'
RSpec.describe Bitcoin::Message::SendAddrV2 do

  it 'should generate sendaddrv2 message', network: :regtest do
    send_addr_v2 = Bitcoin::Message::SendAddrV2.new
    expect(send_addr_v2.to_pkt.bth).to eq('fabfb5da73656e646164647276320000000000005df6e0e2')
  end

end