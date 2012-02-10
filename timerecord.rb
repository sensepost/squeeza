class TimeRecord
	def initialize(block_size, time_per_block)
		@timeout = time_per_block
		@timers = []
		@block_size = block_size
	end

	def mark(line_start, line_end, byte_start, byte_end)
		now = Time.new
		block_starts = []
		if byte_end.is_a?Fixnum
			byte_start.step(byte_end, block_size) {|byte|
				block_starts << {"byte" => byte, "time" => now }
			}
		else
			block_starts = {"time" => now }
		end
		line_start.upto(line_end){|line_num|
			@timers[line_num] = block_starts
		}
	end
	
	def timedout?(line_start, start_byte, end_byte)
		if @timers[line_start].nil?
			Debug.error("Can't determine if the requested block [#{line_start}:#{start_byte}--#{end_byte}] has timed out")
			return false
		end

		block_starts = @timers[line_start]

		now = Time.new
		if block_starts.is_a?Array
			#not whole line, as an endbyte was specified
			block_starts.each{|block|
				if block['byte'] == start_byte 
					if now - block['time'] > @timeout
						return true
					else
						return false
					end
				end
			}
		else #no endbyte, just a time for the whoe line
			if now - block_starts['time'] > @timeout
				return true
			end
		end
		return false
	end
end

