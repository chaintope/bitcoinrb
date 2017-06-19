module Bitcoin
  module Message

    # getdadta message
    # https://bitcoin.org/en/developer-reference#getdata
    class GetData < Base
      include InventoriesParser
      extend InventoriesParser

      COMMAND ='getdata'

      attr_reader :inventories

      def initialize(inventories = [])
        @inventories = inventories
      end

    end

  end
end
