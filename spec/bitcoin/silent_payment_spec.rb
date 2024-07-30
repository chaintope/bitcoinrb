require 'spec_helper'

RSpec.describe Bitcoin::SilentPayment, network: :mainnet do

  describe 'BIP352 Test Vector' do
    it do
      vectors = fixture_file('bip352/send_and_receive_test_vectors.json')
      vectors.each do |v|
        v['sending'].each do |s|
          d = s['given']
          recipients = d['recipients'].map do |r|
            Bitcoin::SilentPayment::Addr.from_string(r)
          end
          expect(recipients.map(&:to_s)).to eq(d['recipients'])
        end
      end
    end
  end
end