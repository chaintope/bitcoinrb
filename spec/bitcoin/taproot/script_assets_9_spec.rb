require 'spec_helper'
require 'bitcoin/taproot/taproot_spec_helper'

RSpec.describe 'script_assets_test_9' do

  let(:spec_path) { fixture_path('taproot/script_assets_test_9.json') }

  it 'should be pass.' do
    test_script_assets(spec_path)
  end
end
