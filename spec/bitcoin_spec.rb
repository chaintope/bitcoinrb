require 'spec_helper'

describe Bitcoin do
  it 'has a version number' do
    expect(Bitcoin::VERSION).not_to be nil
  end
end
