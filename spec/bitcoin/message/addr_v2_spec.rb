require 'spec_helper'

RSpec.describe Bitcoin::Message::AddrV2 do

  describe 'to_payload and parse_from_payload', network: :regtest do
    subject {
      Bitcoin::Message::Base.from_pkt('fabfb5da61646472763200000000000083000000c849f3b80a70cc29600901047b7b7b00208d71cc29600901047b7b7b01208e72cc29600901047b7b7b02208f73cc29600901047b7b7b03209074cc29600901047b7b7b04209175cc29600901047b7b7b05209276cc29600901047b7b7b06209377cc29600901047b7b7b07209478cc29600901047b7b7b08209579cc29600901047b7b7b092096'.htb)
    }
    it 'should parse payload' do
      expect(subject).to be_a(Bitcoin::Message::AddrV2)
      expect(subject.addrs.size).to eq(10)
      expect(subject.addrs[0].addr)
      expect(subject.addrs[0].net).to eq(Bitcoin::Message::NETWORK_ID[:ipv4])
      expect(subject.to_pkt.bth).to eq('fabfb5da61646472763200000000000083000000c849f3b80a70cc29600901047b7b7b00208d71cc29600901047b7b7b01208e72cc29600901047b7b7b02208f73cc29600901047b7b7b03209074cc29600901047b7b7b04209175cc29600901047b7b7b05209276cc29600901047b7b7b06209377cc29600901047b7b7b07209478cc29600901047b7b7b08209579cc29600901047b7b7b092096')
    end
  end

end