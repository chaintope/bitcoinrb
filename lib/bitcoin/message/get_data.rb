module Bitcoin
  module Message

    # getdadta message
    # https://bitcoin.org/en/developer-reference#getdata
    class GetData < Base
      include InventoriesParser
      extend InventoriesParser

      attr_reader :inventories

      def initialize(inventories = [])
        @inventories = inventories
      end

      def command
        'getdata'
      end

    end

  end
end
