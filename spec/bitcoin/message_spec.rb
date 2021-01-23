require 'spec_helper'

RSpec.describe Bitcoin::Message do

  describe '#decode' do
    it 'generate message object corresponding to the command.' do
      ver = Bitcoin::Message.decode('version', '721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
      expect(ver).to be_a(Bitcoin::Message::Version)
      expect(ver.to_hex).to eq('721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')

      ack = Bitcoin::Message.decode('verack')
      expect(ack).to be_a(Bitcoin::Message::VerAck)
    end
  end

end