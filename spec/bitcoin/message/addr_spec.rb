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

end
