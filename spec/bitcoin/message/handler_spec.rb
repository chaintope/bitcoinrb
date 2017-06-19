require 'spec_helper'

describe Bitcoin::Message::Handler do

  subject { Bitcoin::Message::Handler.new }

  describe 'handle message' do

    context 'invalid header size' do
      it 'raise message error' do
        expect { subject.handle('hoge'.htb) }.to raise_error Bitcoin::Message::Error
        expect { subject.handle('') }.to raise_error Bitcoin::Message::Error
      end
    end

    context 'invalid header magic' do
      it 'raise message error' do # mainnet magic
        expect {subject.handle('f9beb4d976657261636b000000000000000000005df6e0e2'.htb)}.to raise_error Bitcoin::Message::Error
      end
    end

    context 'correct header' do
      it 'parse message' do
        expect {subject.handle('0b11090776657261636b000000000000000000005df6e0e2'.htb)}.not_to raise_error Bitcoin::Message::Error
      end
    end

  end

end
