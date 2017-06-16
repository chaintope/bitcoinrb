require 'spec_helper'

describe Bitcoin::Message::Version do

  describe 'to_payload and parse_from_payload' do
    subject {
      version = Bitcoin::Message::Version.new
      version.start_height = 50_000
      @nonce = version.nonce
      version.remote_addr = '83.243.59.57:8333'
      version.relay = false
      Bitcoin::Message::Version.parse_from_payload(version.to_payload)
    }
    it 'should parse payload' do
      expect(subject.services).to eq(0)
      expect(subject.user_agent).to eq(Bitcoin::Message::USER_AGENT)
      expect(subject.local_addr).to eq('83.243.59.57:8333')
      expect(subject.relay).to eq(false)
      expect(subject.nonce).to eq(@nonce)
      expect(subject.start_height).to eq(50_000)
    end
  end

end