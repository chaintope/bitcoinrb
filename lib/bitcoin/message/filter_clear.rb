module Bitcoin
  module Message

    # filterclear message
    # https://bitcoin.org/en/developer-reference#filterclear
    class FilterClear < Base

      COMMAND = 'filterclear'

      def to_payload
        ''
      end

    end

  end
end
