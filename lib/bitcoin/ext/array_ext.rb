module Bitcoin
  module Ext
    module ArrayExt

      refine Array do

        # resize array content with +initial_value+.
        # expect to behave like vec#resize in c++.
        # @raise [ArgumentError] If +new_size+ is not a non-negative integer. A negative size would
        # otherwise empty the array.
        def resize!(new_size, initial_value = 0)
          raise ArgumentError, 'new_size must be a non-negative integer.' unless new_size.is_a?(Integer) && new_size >= 0
          if size < new_size
            (new_size - size).times{self.<< initial_value}
          elsif size > new_size
            (size - new_size).times{delete_at(-1)}
          end
          self
        end

      end

    end
  end
end