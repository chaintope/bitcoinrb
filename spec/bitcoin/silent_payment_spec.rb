require 'spec_helper'

RSpec.describe Bitcoin::SilentPayment, network: :mainnet do

  describe 'BIP352 Test Vector' do
    it do
      vectors = fixture_file('bip352/send_and_receive_test_vectors.json')
      vectors.each do |v|
        v['sending'].each do |s|
          d = s['given']
          tx = Bitcoin::Tx.new
          private_keys = []
          prevouts = []
          d['vin'].each do |i|
            input = Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.from_txid(i['txid'], i['vout']),
                                      script_sig: Bitcoin::Script.parse_from_payload(i['scriptSig'].htb),
                                      script_witness: Bitcoin::ScriptWitness.parse_from_payload(i['txinwitness'].htb))
            tx.in << input
            private_keys << i['private_key'].to_i(16)
            prevouts << Bitcoin::Script.parse_from_payload(i['prevout']['scriptPubKey']['hex'].htb)
          end
          recipients = d['recipients'].map { |r| Bech32::SilentPaymentAddr.parse(r)}
          outputs = tx.derive_payment_points(prevouts, private_keys, recipients)
          expect(outputs.map{|o|o.x.to_s(16)}).to have_same_elements_as_any_of(s['expected']['outputs'])
        end
      end
    end
  end
end