require 'socket'

class PassthruShell
	@module = nil
	
	def help
	end

	def initialize(config)
		@config = config
		@module = @config.getv("module_ref")
		if @config.getv("mssql_mode") != "sql"
			Debug.error("When combined with reDuh, I can only perform using the SQL mode")
			exit(1)
		end
	end

	def setusupthesocket
		@ss = TCPServer.new(@config.getv("listen_addr"), @config.getv("listen_port"))
		if @ss.nil?
			Debug.error("Could not create listening socket")
			raise Exception.new("Could not create listening socket")
		end
	end

	def run
		setusupthesocket

		begin

			Debug.print("Started command loop",2)
			
			trap("EXIT") { puts "\nExited" }
			trap("SIGINT") {puts"Ctrl-C"; exit }
      Thread.start(@ss.accept) do |socket|
				begin
				while input = socket.gets
					input.strip!
					(switch,command) = input.split(/\|/,2)
					Debug.print("Got command from socket")
					Debug.print(command)
					case command
					when /SELECT/
						command =~ /SELECT (.*) FROM (.*) WHERE (.*)/
						columns = $1
						table = $2
						where_clause = $3
						order_by = where_clause.split("ORDER BY")
						if order_by.length == 2
							where_clause = order_by[0]
							order_by = order_by[1]
						end
						oneline = false
						if columns =~ /TOP 1/
							oneline = true
							columns.sub!(/TOP 1/,'')
						end
						columns = columns.gsub(/ /,'').gsub(/,/,"+'|'+")
						columns.sub!(/out_number/,"cast(out_number as varchar(10))")
						table.gsub!(/ /,'')
						command = {"column"=>columns, "table" => table, "where_clause" => where_clause, "order_by" => order_by,"oneline" => ((oneline)?"true" : "")}
						Debug.print(command)
						
						begin	
						@module.send_formatted_cmd(command) {|linenum,line| Debug.print(line);socket.write(line.strip+"\n")}
						rescue Exception => e
							Debug.print("SELECT socket exception: #{e.to_s}")
						end

					when /(INSERT|DELETE)/
						puts "here"
						Debug.print("passthru: "+command)
						command = {"passthru" => "true", "statement" => command}
						begin
							@module.send_formatted_cmd(command)
						rescue Exception => e
							Debug.print("INSERT socket exception: #{e.to_s}")
						end
					end
					socket.write("ZZZZZZZZZZ\n");
				end
				rescue Exception => e
					Debug.print("socket closed: #{e.to_s}")
				end
			end

		end until false
		
	end

end

