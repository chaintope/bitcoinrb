require 'spec_helper'

describe Bitcoin::Message::MemPool do

  describe 'to_pkt' do
    subject {
      Bitcoin::Message::MemPool.new.to_pkt
    }
    it 'should be generate' do
      expect(subject).to eq('0b1109076d656d706f6f6c0000000000000000005df6e0e2'.htb)
    end
  end

end
