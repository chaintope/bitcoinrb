require 'spec_helper'

describe Bitcoin::Message::VerAck do

  subject {
    Bitcoin::Message::VerAck.new
  }

  it 'should be generate verack message' do
    expect(subject.to_pkt.bth).to eq('0b11090776657261636b000000000000000000005df6e0e2')
  end

end