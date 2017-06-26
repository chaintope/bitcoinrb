require 'spec_helper'

describe Bitcoin::Message::Reject do

  describe 'parse from payload' do
    subject {
      Bitcoin::Message::Reject.parse_from_payload('0274781008636f696e62617365b593848d99f41a45e9d29054993139f0582025bb45191986bc0d81327fc4ed4e'.htb)
    }
    it 'should be parsed' do
      expect(subject.message).to eq('tx')
      expect(subject.code).to eq(0x10)
      expect(subject.reason).to eq('coinbase')
      expect(subject.extra).to eq('4eedc47f32810dbc86191945bb252058f03931995490d2e9451af4998d8493b5')
      expect(subject.to_payload).to eq('0274781008636f696e62617365b593848d99f41a45e9d29054993139f0582025bb45191986bc0d81327fc4ed4e'.htb)
    end
  end

  describe 'to_pkt' do
    subject {
      Bitcoin::Message::Reject.new('tx', Bitcoin::Message::Reject::CODE_INVALID,
                                   'coinbase', '4eedc47f32810dbc86191945bb252058f03931995490d2e9451af4998d8493b5').to_pkt
    }
    it 'should be generate' do
      expect(subject).to eq('0b11090772656a6563740000000000002d0000005b2e22a70274781008636f696e62617365b593848d99f41a45e9d29054993139f0582025bb45191986bc0d81327fc4ed4e'.htb)
    end
  end

end