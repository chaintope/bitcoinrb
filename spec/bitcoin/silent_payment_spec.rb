require 'spec_helper'

RSpec.describe Bitcoin::SilentPayment, network: :mainnet, use_secp256k1: true do

  describe 'BIP352 Test Vector' do
    it do
      vectors = fixture_file('bip352/send_and_receive_test_vectors.json')
      vectors.each do |v|
        puts v['comment']
        is_k_max_test = v['comment'].include?('K_max')

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
            private_keys << Bitcoin::Key.new(priv_key: i['private_key'])
            prevouts << Bitcoin::Script.parse_from_payload(i['prevout']['scriptPubKey']['hex'].htb)
          end
          # Expand recipients with count field
          recipients = d['recipients'].flat_map do |r|
            count = r['count'] || 1
            Array.new(count) { Bech32::SilentPaymentAddr.parse(r['address']) }
          end

          if is_k_max_test
            # K_max exceeded: expect ArgumentError
            expect { tx.derive_payment_points(prevouts, private_keys, recipients) }.to raise_error(ArgumentError, /K_max/)
          else
            outputs = tx.derive_payment_points(prevouts, private_keys, recipients)
            expect(outputs.map{|o|o.x.to_s(16)}).to have_same_elements_as_any_of(s['expected']['outputs'])
          end
        end

        v['receiving'].each do |r| # for receiver
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

          # Handle K_max test case with n_outputs format
          if r['expected']['n_outputs']
            expect(outputs.length).to eq(r['expected']['n_outputs'])
          else
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
end