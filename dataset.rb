

class LineUnderflow < Exception
end

class LineOverflow < Exception
	def initialize(byte_start, block_size)
		@byte_start = byte_start
		@block_size = block_size
	end

	def to_s
		"byte_start = #{@byte_start}, block_size = #{@block_size}"
	end

end

class InvalidLineIndex < Exception
end

class ReliabilityError < Exception
end

class LengthException < Exception
end

class MisalignedBlock < Exception
	def initialize(byte_start, block_size)
		@byte_start = byte_start
		@block_size = block_size
	end

	def to_s
		"byte_start = #{@byte_start}, block_size = #{@block_size}"
	end
end

class Block
	attr(:block_content)

	def initialize(block_start_byte, block_content)
		@block_start_byte=block_start_byte
		@block_content = block_content
	end

	def block_length
		@block_content.length
	end
end

class DataLine
	
	def initialize(block_size,line_length)
	
		#calculate number of blocks in a line. if line_length is wholey divisible by the block_size, no remaining bytes need to be accounted for
		#we also permit empty lines, these require one zero-length block
		num_blocks = line_length/block_size
		num_blocks += 1 if line_length % block_size != 0  
		num_blocks = 1 if line_length == 0
		@blocks = Array.new(num_blocks)

		@line_length = line_length
		@stored_line_length = 0
		@block_size = block_size
		@complete = false
	end

	def complete?

		return @complete if @complete

		total_length = 0
		@blocks.each{|block|
			total_length+=block.block_length if !block.nil?
		}
		Debug.print("   line_length=#{@line_length}",2)
		Debug.print("   blocks=#{@blocks.length}",2)
		Debug.print("   total_length=#{total_length}",2)
		if total_length == @line_length
			@complete = true
			return true
		elsif total_length < @line_length
			return false
		else
			raise LengthException
		end
	end

	def get_empty_blocks
		empty_blocks = []
		0.upto(@blocks.length-1){|index|
			#@block_size+1 is the conversion to 1-based byte counts
			empty_blocks << (index*@block_size+1) if @blocks[index].nil?
		}
		empty_blocks
	end

	def insert(byte_start, content)

		raise MisalignedBlock.new(byte_start, @block_size) if byte_start % @block_size != 0
		
		index = byte_start/@block_size
		raise LineOverflow.new(index,@blocks.length) if index > @blocks.length - 1

		if @blocks[index].nil?
			@blocks[index] = Block.new(byte_start, content)
			@stored_line_length += content.length

			#catch those cases when we get more data than expected
			raise ReliabilityError if @stored_line_length > @line_length 
			#catch those cases when a short line is received
			#addendum: hard to figure out, 'cos we might still be waiting for input
			#raise LineUnderflow if content.length < @block_size && @stored_line_length != @line_length
		else
			#we don't overwrote anthying if the block already has contents
		end

	end

	def line
		line_content = ""	
		@blocks.each{|block|
			line_content += block.block_content if !block.nil?
		}
		line_content
	end
end

class DataSet
	def initialize(block_size)
		@lines = []
		@num_lines = 0
		@block_size = block_size
		@complete = false
		@final_entry = 2**32
	end
	
	def endofsql?
		@complete
	end

	def endofsql=(val)
		@complete = val
	end

	def dataset_end(line_num)
		line_num -= 1

		self.endofsql=true
		@lines[line_num] = :dataend
		@final_entry = line_num
	end

	def insert(line_num, byte_start, line_length, line_content)
		#indexing conversion from 1-based to 0-based
		Debug.print("dataset.insert [#{line_num}:#{byte_start}:#{line_length}]",2)

		line_num -= 1
		byte_start -=1
		@lines[line_num] = DataLine.new(@block_size,line_length) if @lines[line_num].nil?

		@lines[line_num].insert(byte_start, line_content) 
		@num_lines+= 1
	end

	def complete?(line_num)
		#indexing conversion from 1-based to 0-based
		Debug.print("Checking for completeness on line #{line_num}",2)
		line_num -= 1
		
		@lines[line_num].complete?
	end

	def empty_blocks(line_num)
		Debug.print("Entered empty_blocks with line_num = #{line_num}",2)
		working = empty_blocks_per_row(line_num)
		return working if working.length == 0

		empty_blocks = []
		working.each{|blck|
			if blck['blocks_start']
				blck["blocks_start"].each{|blck_start| empty_blocks << {"line_num"=>blck["line_num"],"block_start"=>blck_start} }
			else
				empty_blocks << {"line_num"=>blck["line_num"], "block_start"=>1}
			end
		}
		Debug.print("Exiting empty_blocks with empty_blocks = #{empty_blocks}",2)
		empty_blocks
	end
	
	def delete(line_num)
		line_num -= 1
		@lines.delete_at(line_num)
	end

	def [](line_num)
		#indexing conversion from 1-based to 0-based
		line_num -= 1

		raise InvalidLineIndex if line_num > @lines.length - 1

		if @lines[line_num].is_a?(DataLine) && @lines[line_num].complete?
			return @lines[line_num].line 
		else
			return nil
		end
	end

	def each(line_range, &block)
		(line_range.first-1).upto(line_range.last-1){|index|
			block.call(index+1,@lines[index].line) if @lines[index].is_a?DataLine
		}
	end
	
	def row_count
		@lines.length
	end

private

	#don't call this externally, it still uses the 0-based
	def empty_blocks_per_row(line_num)
		if line_num.is_a?Range
			blocks = []
			(line_num.first-1).upto(line_num.last-1){|index|
				if @lines[index]
					if @lines[index] != :dataend
						empty_block_list = @lines[index].get_empty_blocks
						blocks << {"line_num" => index+1, "blocks_start" => empty_block_list} if empty_block_list.length > 0
					end
				elsif index < @final_entry
					blocks << {"line_num" => index+1, "blocks_start" => nil} 
				end
			}
			return blocks.compact
		else
			#indexing conversion from 1-based to 0-based
			line_num -= 1

			return [{"line_num" => line_num, "blocks_start" => @lines[line_num].get_empty_blocks}]
		end
	end


end

#d = DataLine.new(20,50)
#d.insert(1,0,"you are a sillly cat")
#d.insert(20,"you are a stupid cat")
#d.insert(40,"dum dog!!!")
#d.insert(20,"you are a stupid cat")
#d.insert(40,"dum dog!!!")
#if d.complete?
#	puts " all done"
#	puts d.line
#else
#	puts "still waiting"
#end

if false
line = []
line[0] = "real short"
line[2] = "that position is somewhat short"
line[3] = "and, by necessity, we make this line a little longer than line 2, but shorter than line 1"

s = DataSet.new(20)
s.insert(1, 0,line[0].length,line[0])
s.insert(2,20,50,"n been said that the")
s.insert(2,40,50," dogs suck")
s.insert(2, 0,50,"although it has ofte")
s.insert(3,0,20, "this is a qqqqqqqqqq")
s.insert(4,40,60, "this is a block 3of3")
s.insert(4,20,60, "this is a block 2of3")
s.insert(4,20,60, "this is a block 2of3")
s.insert(4,20,60, "this is a block 2of3")
s.insert(5,0,20, "this is a zzzzzzzzzz")
s.insert(4,0,60, "this is a block 1of3")
s.insert(2,40,50," dogs suck")
s.insert(2,40,50," dogs suck")
s.insert(5,0,20, "this is a zzzzzzzzzz")

1.upto(s.row_count){|x| 
	if s.complete?(x) 
		puts s[x] 
	else 
		puts s.empty_blocks(x)
	end}
end
