require 'spec_helper'

describe Bitcoin::Message::SendHeaders do

  describe 'to_pkt' do
    subject {
      Bitcoin::Message::SendHeaders.new.to_pkt
    }
    it do
      expect(subject).to eq('0b11090773656e646865616465727300000000005df6e0e2'.htb)
    end
  end

end