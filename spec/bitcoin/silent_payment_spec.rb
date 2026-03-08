require 'spec_helper'

RSpec.describe Bitcoin::SilentPayment, network: :mainnet do

  describe 'BIP352 Test Vector' do
    it do
      vectors = fixture_file('bip352/send_and_receive_test_vectors.json')
      vectors.each do |v|
        v['sending'].each do |s| # for sender
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

        v['receiving'].each do |r| # for receiver
          puts ['']
          d = r['given']
          tx = Bitcoin::Tx.new
          prevouts = []
          d['vin'].each do |i|
            input = Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.from_txid(i['txid'], i['vout']),
                                      script_sig: Bitcoin::Script.parse_from_payload(i['scriptSig'].htb),
                                      script_witness: Bitcoin::ScriptWitness.parse_from_payload(i['txinwitness'].htb))
            tx.in << input
            prevouts << Bitcoin::Script.parse_from_payload(i['prevout']['scriptPubKey']['hex'].htb)
          end
          d['outputs'].each do |o|
            begin
              tx.out << Bitcoin::TxOut.new(script_pubkey: Bitcoin::Script.to_p2tr(Bitcoin::Key.from_xonly_pubkey(o)))
            rescue ArgumentError
              # Ignored
            end
          end
          scan_priv_key = Bitcoin::Key.new(priv_key: d['key_material']['scan_priv_key'])
          spend_pubkey = Bitcoin::Key.new(priv_key: d['key_material']['spend_priv_key'])
          labels = d['labels'] || []
          outputs = tx.scan_sp_outputs(prevouts, scan_priv_key, spend_pubkey, labels)
          expect(outputs.length).to eq(r['expected']['outputs'].length)
          expected_pub_keys = r['expected']['outputs'].map { |o| o['pub_key'] }
          actual_pub_keys = outputs.map(&:pubkey)
          expect(actual_pub_keys).to match_array(expected_pub_keys)
          # Verify tweak values
          expected_tweaks = r['expected']['outputs'].map { |o| o['priv_key_tweak'] }
          actual_tweaks = outputs.map(&:tweak_hex)
          expect(actual_tweaks).to match_array(expected_tweaks)
        end
      end
    end
  end
end