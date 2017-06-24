require 'spec_helper'

describe Bitcoin::Message::Addr do

  describe 'to_pkt' do
    subject{
      addr = Bitcoin::Message::NetworkAddr.new
      addr.ip = '92.169.156.82'
      addr.port = 18333
      addr.time = 2989705664
      addr.services = 1
      Bitcoin::Message::Addr.new([addr]).to_pkt
    }
    it 'should be generate' do
      expect(subject).to eq('0b1109076164647200000000000000001f0000003d9273fa01c04933b2010000000000000000000000000000000000ffff5ca99c52479d'.htb)
    end
  end

  describe 'parse from payload' do
    subject {
      Bitcoin::Message::Addr.parse_from_payload('01c04933b2010000000000000000000000000000000000ffff5ca99c52479d'.htb)
    }
    it 'should be parsed' do
      expect(subject.addrs.length).to eq(1)
      expect(subject.addrs[0].ip).to eq('92.169.156.82')
      expect(subject.addrs[0].port).to eq(18333)
      expect(subject.addrs[0].time).to eq(2989705664)
      expect(subject.addrs[0].services).to eq(1)
    end
  end

end
