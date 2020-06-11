require 'spec_helper'

describe Bitcoin::Message::CFCheckpt do

  describe '#parse_from_payload', network: :regtest do
    subject {
      Bitcoin::Message::CFCheckpt.parse_from_payload('003212f2fefbc11b3785b6b0747a89f645946a4fd97909f12d3f6b796ee9aea81001b8f0c5394bd31f1810b5b815943620b8a0bd4fa6717f6da8061a3fbdc51fca8d'.htb)
    }
    it 'should be parsed.' do
      expect(subject.filter_type).to eq(0)
      expect(subject.stop_hash).to eq('3212f2fefbc11b3785b6b0747a89f645946a4fd97909f12d3f6b796ee9aea810')
      expect(subject.stop_hash.htb.bytesize).to eq(32)
      expect(subject.filter_headers.size).to eq(1)
      expect(subject.filter_headers.first).to eq('b8f0c5394bd31f1810b5b815943620b8a0bd4fa6717f6da8061a3fbdc51fca8d')
      expect(subject.filter_headers.first.htb.bytesize).to eq(32)
      expect(subject.to_pkt.bth).to eq('fabfb5da6366636865636b7074000000420000009f0ac0cb003212f2fefbc11b3785b6b0747a89f645946a4fd97909f12d3f6b796ee9aea81001b8f0c5394bd31f1810b5b815943620b8a0bd4fa6717f6da8061a3fbdc51fca8d')
    end
  end

end