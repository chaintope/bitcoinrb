module Bitcoin
  module Message

    # notfound message
    # https://bitcoin.org/en/developer-reference#notfound
    class NotFound < Base
      include InventoriesParser
      extend InventoriesParser

      attr_reader :inventories

      COMMAND = 'notfound'

      def initialize(inventories = [])
        @inventories = inventories
      end

    end
  end

end
