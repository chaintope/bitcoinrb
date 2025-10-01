require 'spec_helper'

RSpec.describe Bitcoin::BIP321URI do

  context 'mainnet', network: :mainnet do
    it do
      raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses.first).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
      expect(uri.to_s).to eq(raw_uri)

      raw_uri = 'BITCOIN:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?label=Luke-Jr'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses.first).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
      expect(uri.label).to eq('Luke-Jr')
      expect(uri.to_s).to eq('bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?label=Luke-Jr')

      raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?amount=20.3&label=Luke-Jr'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses.first).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
      expect(uri.label).to eq('Luke-Jr')
      expect(uri.amount).to eq(20.3)
      expect(uri.satoshi).to eq(2_030_000_000)
      expect(uri.to_s).to eq(raw_uri)

      raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses.first).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
      expect(uri.label).to eq('Luke-Jr')
      expect(uri.amount).to eq(50.0)
      expect(uri.satoshi).to eq(5_000_000_000)
      expect(uri.message).to eq('Donation for project xyz')
      expect(uri.to_s).to eq(raw_uri)

      raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?somethingyoudontunderstand=50&somethingelseyoudontget=999'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses.first).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
      expect(uri.other_params).to eq({"somethingyoudontunderstand" => '50', "somethingelseyoudontget" => '999'})
      expect(uri.to_s).to eq(raw_uri)

      expect{described_class.parse('bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999')}.
        to raise_error(ArgumentError, /An unsupported reqparam is included./)

      expect{described_class.parse('bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W')}.
        to raise_error(ArgumentError, /Invalid address/)

      raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?lightning=lnbc420bogusinvoice'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses.first).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
      expect(uri.lightning).to eq('lnbc420bogusinvoice')

      raw_uri = 'bitcoin:?lightning=lnbc420bogusinvoice'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses).to be_empty
      expect(uri.lightning).to eq('lnbc420bogusinvoice')
      expect(uri.to_s).to eq(raw_uri)

      raw_uri = 'bitcoin:?lno=lno1bogusoffer'
      uri = described_class.parse(raw_uri)
      expect(uri.lno).to eq('lno1bogusoffer')

      raw_uri = 'bitcoin:?lno=lno1bogusoffer&sp=sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv'
      uri = described_class.parse(raw_uri)
      expect(uri.lno).to eq('lno1bogusoffer')
      expect(uri.sp).to eq('sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv')
      expect(uri.to_s).to eq(raw_uri)

      raw_uri = 'bitcoin:?sp=sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv'
      uri = described_class.parse(raw_uri)
      expect(uri.sp).to eq('sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv')

      raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?sp=sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses.first).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
      expect(uri.sp).to eq('sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv')
      expect(uri.req_pop).to be false

      raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?req-pop=callback%3A'
      uri = described_class.parse(raw_uri)
      expect(uri.pop).to eq('callback:')
      expect(uri.req_pop).to be true
      expect(uri.to_s).to eq(raw_uri)

      # Multiple segwit addresses may be included for various versions of segwit, note that the human-readable part for all of them is `bc`
      raw_uri = 'bitcoin:?bc=bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5n2&bc=bc1p5swkugezn97763tl0yty6556856uug0q6jflljvep9m4p7339x5qzyrh4g'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses).to eq(%w[bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5n2 bc1p5swkugezn97763tl0yty6556856uug0q6jflljvep9m4p7339x5qzyrh4g])
      expect(uri.to_s).to eq(raw_uri)

      # Many QR codes utilize all-uppercase URIs, which should be handled fine
      raw_uri = 'BITCOIN:BC1QUFGY354J3KMVUCH987XE4S40836X3H0LG8F5N2?BC=BC1P5SWKUGEZN97763TL0YTY6556856UUG0Q6JFLLJVEP9M4P7339X5QZYRH4G'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses).to eq(%w[BC1QUFGY354J3KMVUCH987XE4S40836X3H0LG8F5N2 BC1P5SWKUGEZN97763TL0YTY6556856UUG0Q6JFLLJVEP9M4P7339X5QZYRH4G])
      expect(uri.to_s.upcase).to eq(raw_uri)

      raw_uri = 'BITCOIN:?BC=BC1QUFGY354J3KMVUCH987XE4S40836X3H0LG8F5N2&BC=BC1P5SWKUGEZN97763TL0YTY6556856UUG0Q6JFLLJVEP9M4P7339X5QZYRH4G'
      uri = described_class.parse(raw_uri)
      expect(uri.addresses).to eq(%w[BC1QUFGY354J3KMVUCH987XE4S40836X3H0LG8F5N2 BC1P5SWKUGEZN97763TL0YTY6556856UUG0Q6JFLLJVEP9M4P7339X5QZYRH4G])
      expect(uri.to_s.upcase).to eq(raw_uri)

      # Labels must not appear twice:
      raw_uri = 'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Luke-Jr&label=Matt'
      expect{described_class.parse(raw_uri)}.to raise_error(ArgumentError, /label must not appear twice./)

      # Amounts must not appear twice:
      raw_uri = 'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=42&amount=10'
      expect{described_class.parse(raw_uri)}.to raise_error(ArgumentError, /amount must not appear twice./)

      # Amounts must not appear twice even if they are the same:
      raw_uri = 'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=42&amount=42'
      expect{described_class.parse(raw_uri)}.to raise_error(ArgumentError, /amount must not appear twice./)

      # Multiple proof of payment URIs must not appear, even if they are sometimes prefixed with req-:
      raw_uri = 'bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?pop=callback%3a&req-pop=callback%3a'
      expect{described_class.parse(raw_uri)}.to raise_error(ArgumentError, /pop must not appear twice./)

      # Invalid sp address
      expect{described_class.parse('bitcoin:?sp=sp1qsilentpayment')}.to raise_error(ArgumentError, /Invalid sp address specified./)
    end
  end

  context 'testnet', network: :testnet do
    it do
      # A testnet segwit addresses must be included in the `tb` parameter
      raw_uri = 'bitcoin:?tb=tb1qghfhmd4zh7ncpmxl3qzhmq566jk8ckq4gafnmg'
      uri = described_class.parse(raw_uri)
      expect(uri.to_s).to eq(raw_uri)

      # A testnet segwit addresses must be included in the `tb` parameter, not the `bc` parameter.
      raw_uri = 'bitcoin:?bc=tb1qghfhmd4zh7ncpmxl3qzhmq566jk8ckq4gafnmg'
      expect{described_class.parse(raw_uri)}.to raise_error(ArgumentError, "bc not allowed in current network.")
    end
  end
end