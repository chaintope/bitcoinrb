require 'spec_helper'

describe Bitcoin::Message::GetAddr do

  describe 'to_pkt' do
    subject {
      Bitcoin::Message::GetAddr.new.to_pkt
    }
    it do
      expect(subject).to eq('0b110907676574616464720000000000000000005df6e0e2'.htb)
    end
  end

end