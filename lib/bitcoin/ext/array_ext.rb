module Bitcoin
  module Ext
    module ArrayExt

      refine Array do

        # resize array content with +initial_value+.
        # expect to behave like vec#resize in c++.
        def resize!(new_size, initial_value = 0)
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