class SqueezaShell
	@module = nil
	
	def help
		puts "shell commands and variables"
		puts " commands"
		puts "  !help : shows all help for current module"
		puts "  !quit : exit"
		puts " variables"
		puts "  prompt : prompt to display"
	end

	def initialize(config)
		@config = config
		@module = @config.getv("module_ref")
		@config.setv("prompt", "sp-sq>")
		@exit_now = false

		@config.set_command("quit") { exit_at_end_of_loop }
		@config.set_command("help") { help; @config.help; @module.help;}
		@config.set_command("set")  {|cmd| @config.interpret_set(cmd)}
		@config.set_command("debug")  {|level| Debug.set_level(level.to_i)}

		#puts @config.loaded_module
	end

	def build_prompt
		@prompt = @config.getv("prompt").strip+" "
	end
	
	def exit_requested?
		return @exit_now
	end

	def exit_at_end_of_loop
		@exit_now = true
	end

	def run

		begin
			trap("EXIT") { puts "\nExited" }
			trap("SIGINT") { exit }

			print build_prompt
			
			command = $stdin.gets

			if (command.nil?)
				exit_at_end_of_loop
				next
			elsif (command.strip.length == 0)
				next
			else
				command.strip!
			end
			
			if (command == "?" || command == "help")
				Debug.print("If you're looking for Squeeza help, please use !help; your command \"#{command}\" is on its way to the target",0)
			end

			if command[0] == ?!
				#commands start with !, find handler for command
				command[/!(.*?)( |$)/]
				cmd = $1
				if !cmd.nil?
					cmd.strip!
				else
					Debug.print("Nil command: #{command}, #{cmd}", 2)
				end

				args = command[/ .*/]
				if !args.nil?
					args.strip!
				end
				
				block = @config.get_command(cmd)
				if block.nil?
					#no handler for this command, pass to module by default
					#@module.send_cmd(command)
					Debug.error("Unknown command \"#{cmd}\"")
				else
					#we have a handler, let's use it!
					block.call(args)
				end
			else
				#no hanlder, send through to module
				@module.send_cmd(command)
			end

		end until exit_requested?
		
	end

end

