require 'spec_helper'

RSpec.describe Bitcoin::BIP21URI, network: :mainnet do

  it do
    raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym'
    uri = described_class.parse(raw_uri)
    expect(uri.address).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
    expect(uri.to_s).to eq(raw_uri)

    raw_uri = 'BITCOIN:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?label=Luke-Jr'
    uri = described_class.parse(raw_uri)
    expect(uri.address).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
    expect(uri.label).to eq('Luke-Jr')
    expect(uri.to_s).to eq('bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?label=Luke-Jr')

    raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?amount=20.3&label=Luke-Jr'
    uri = described_class.parse(raw_uri)
    expect(uri.address).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
    expect(uri.label).to eq('Luke-Jr')
    expect(uri.amount).to eq(20.3)
    expect(uri.satoshi).to eq(2_030_000_000)
    expect(uri.to_s).to eq(raw_uri)

    raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz'
    uri = described_class.parse(raw_uri)
    expect(uri.address).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
    expect(uri.label).to eq('Luke-Jr')
    expect(uri.amount).to eq(50.0)
    expect(uri.satoshi).to eq(5_000_000_000)
    expect(uri.message).to eq('Donation for project xyz')
    expect(uri.to_s).to eq(raw_uri)

    raw_uri = 'bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?somethingyoudontunderstand=50&somethingelseyoudontget=999'
    uri = described_class.parse(raw_uri)
    expect(uri.address).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
    expect(uri.other_params).to eq({"somethingyoudontunderstand" => '50', "somethingelseyoudontget" => '999'})
    expect(uri.to_s).to eq(raw_uri)

    expect{described_class.parse('bitcoin:17T9tBC2dSpusL1rhT4T4AV4if963Tpfym?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999')}.
      to raise_error(ArgumentError, /An unsupported reqparam is included./)
    
    expect{described_class.parse('bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W')}.
      to raise_error(ArgumentError, /Invalid address/)
  end
end