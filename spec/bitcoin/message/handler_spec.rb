require 'spec_helper'

describe Bitcoin::Message::Handler do

  describe 'handle message' do

    context 'invalid header size' do
      subject { Bitcoin::Message::Handler.new }
      it 'raise message error' do
        expect{ subject.handle('hoge') }.to raise_error Bitcoin::Message::Error
        expect{ subject.handle(nil) }.to raise_error Bitcoin::Message::Error
      end
    end

  end

end