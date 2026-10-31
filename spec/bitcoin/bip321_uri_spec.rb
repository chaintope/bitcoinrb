require 'spec_helper'
require 'open3'

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

      # An address in the query parameters must be separated from the other parameters
      raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?amount=0.1&bc=bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5n2'
      uri = described_class.parse(raw_uri)
      expect(uri.amount).to eq(0.1)
      expect(uri.addresses).to eq(%w[17T9tBC2dSpusL1rhT4T4AV4if963Tpfym bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5n2])
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

  describe 'query parsing rules', network: :mainnet do
    let(:addr) { '17T9tBC2dSpusL1rhT4T4AV4if963Tpfym' }

    it 'should accept only an amount of the form *digit ["." *digit] with at most 8 decimals' do
      { '50' => 5_000_000_000, '50.00' => 5_000_000_000, '1.' => 100_000_000, '.5' => 50_000_000,
        '0.00000001' => 1, '21000000' => 2_100_000_000_000_000 }.each do |value, satoshi|
        expect(described_class.parse("bitcoin:#{addr}?amount=#{value}").satoshi).to eq(satoshi), value
      end
      ['-1', '1e8', '1E-3', '1_000', '0x10', '%201', 'Infinity', 'NaN', '', '.', '50,000.00'].each do |value|
        expect { described_class.parse("bitcoin:#{addr}?amount=#{value}") }.to raise_error(ArgumentError, /Invalid amount/), value
      end
      expect { described_class.parse("bitcoin:#{addr}?amount=0.123456789") }.to raise_error(ArgumentError, /at most 8 decimal places/)
      expect { described_class.parse("bitcoin:#{addr}?amount=21000000.00000001") }.to raise_error(ArgumentError, /exceeds 21000000 BTC/)
    end

    it 'should validate an amount given to the constructor' do
      expect(described_class.new(address: addr, amount: BigDecimal('0.5')).satoshi).to eq(50_000_000)
      expect { described_class.new(address: addr, amount: BigDecimal('-1')) }.to raise_error(ArgumentError, 'amount must not be negative.')
      expect { described_class.new(address: addr, amount: BigDecimal('0.000000001')) }.to raise_error(ArgumentError, /8 decimal places/)
      expect { described_class.new(address: addr, amount: 21_000_001) }.to raise_error(ArgumentError, /must not exceed/)
    end

    it 'should treat the query keys as case-insensitive' do
      uri = described_class.parse("bitcoin:#{addr}?AMOUNT=1&Label=x&REQ-POP=cb%3a")
      expect(uri.satoshi).to eq(100_000_000)
      expect(uri.label).to eq('x')
      expect(uri.pop).to eq('cb:')
      expect(uri.req_pop).to be true
      expect(uri.other_params).to be_empty
      expect { described_class.parse("bitcoin:#{addr}?label=a&LABEL=b") }.to raise_error(ArgumentError, 'label must not appear twice.')
      expect { described_class.parse("bitcoin:#{addr}?Req-foo=1") }.to raise_error(ArgumentError, 'An unsupported reqparam is included.')
      expect(described_class.parse('bitcoin:?BC=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4').addresses).to eq(['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'])
    end

    it 'should percent-decode values as RFC 3986 does, leaving a + as it is' do
      expect(described_class.parse("bitcoin:#{addr}?label=a+b").label).to eq('a+b')
      expect(described_class.parse("bitcoin:#{addr}?label=a%20b%2Bc").label).to eq('a b+c')
      expect(described_class.new(address: addr, label: 'a+b c').to_s).to eq("bitcoin:#{addr}?label=a%2Bb%20c")
    end

    it 'should allow an unknown key more than once and a key without a value' do
      uri = described_class.parse("bitcoin:#{addr}?foo=1&foo=2&bar")
      expect(uri.other_params).to eq({ 'foo' => %w[1 2], 'bar' => nil })
      expect(uri.to_s).to eq("bitcoin:#{addr}?foo=1&foo=2&bar")
      # A key without a value stays in place however many times the key appears.
      uri = described_class.parse("bitcoin:#{addr}?foo&foo=2&foo")
      expect(uri.other_params).to eq({ 'foo' => [nil, '2', nil] })
      expect(uri.to_s).to eq("bitcoin:#{addr}?foo&foo=2&foo")
      expect { described_class.parse("bitcoin:#{addr}?lightning=a&lightning=b") }.to raise_error(ArgumentError, 'lightning must not appear twice.')
    end

    it 'should require the address of a bc parameter to be a bech32 address' do
      expect { described_class.parse("bitcoin:?bc=#{addr}") }.to raise_error(ArgumentError, 'bc must hold a bech32 address with the prefix bc.')
      expect { described_class.parse('bitcoin:?bc=bc1notanaddress') }.to raise_error(ArgumentError, /Invalid address/)
    end

    it 'should parse a URI with neither an address nor a query' do
      uri = described_class.parse('bitcoin:')
      expect(uri.addresses).to be_empty
      expect(uri.amount).to be_nil
      expect(uri.to_s).to eq('bitcoin:')
    end
  end

  describe 'amount parsing in a process which loads nothing but this gem' do
    it 'should parse an amount with only require "bitcoin"' do
      # bigdecimal is a bundled gem since Ruby 3.4 and is not loaded by the interpreter on its own. In the test
      # suite other gems load it, so the check has to run in a fresh process.
      script = 'require "bitcoin"; puts Bitcoin::BIP321URI.parse("bitcoin:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2?amount=1.5").satoshi'
      out, err, status = Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../../lib', __dir__), '-e', script)
      expect(status.success?).to be(true), err
      expect(out.strip).to eq('150000000')
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