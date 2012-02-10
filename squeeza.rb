#!/usr/bin/ruby -w
#squeeza, new age sql injection tool
#Copyright (C) 2007,2008 Marco Slaviero
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; either version 2
#of the License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require 'getoptlong'
require 'squeezashell'
require 'passthru'


version = "0.3"

class Debug
	@@level = 0
	
	def Debug.print(msg, level=0)
		if level <= @@level
			if msg.is_a?(String)
				msg.split(/\n/).each{|x| puts "[sq] #{x}"} 
			elsif msg.is_a?(Hash)
				msg.keys.each{|k| puts "\t\"#{k}\" => \"#{msg[k]}\""}
			end
		end
	end

	def Debug.error(msg)
		msg.split(/\n/).each{|x| $stderr.puts "[sq-err] #{x}"}
	end

	def Debug.set_level(level)
		@@level = level
	end

end

#plugin code from http://eigenclass.org/hiki.rb?ruby+plugins
class SqueezaPlugin
	@module = nil
	@module_name = nil

	def self.inherited(child)
		@module = child
		@module_name = child.to_s
	end
	
	class << self; 
		attr_reader :module;
		attr_reader :module_name; 
	end
end

class SqueezaConfig

	def usage
		puts "\t[--config=|-c ] configfile";
		puts "\t[[--debug=|-v ][1|2|3]]";
		puts "\t[--help|-h]     print help";
		puts "\t[--module=|-m ] module";
	end

	def help
		puts "configuration commands and variables"
		puts " commands"
		puts "  !set var     : shows contents of <var>"
		puts "  !set var=val : sets <var> to <val>"
		puts "  !set         : lists all current vars"
		puts " variables"
		puts "  module : current module in use"
		puts "  ansi   : if set, enable basic status bar-type thingies"
	end

	def getvars
		@vars
	end

	def getv(key)
		return nil if key.nil?
		key = key.chomp.downcase

		return @vars[key] if @vars.has_key?(key)
		return nil
	end

	def setv(key, value)
		return nil if key.nil?

		key = key.chomp.downcase
		old_value = nil
		old_value = @vars[key] if @vars.has_key?(key)
	
		value.chomp! if value.is_a?String

		bracket_start = key =~ /\[\]$/

		if bracket_start.nil?
			#not an array value
			@vars[key] = value
		else
			#array value
			key = key[0...bracket_start]
			@vars[key] = Array.new if @vars[key].nil?
			@vars[key] << value
		end
		old_value
	end

	def read_config(filename)
		lineno = 0
		Debug.print("Reading config file #{filename}",2)
    File.open(filename) do |file|
      file.each_line do |line|
				lineno += 1
        next if line =~ /^\w*$/ or line =~ /^#/
        key, val = line.split(/=/,2)
				Debug.print("Config line #{key} => #{val}",2)
				if (key.kind_of?(String) && val.kind_of?(String))
	        setv(key, val)
				else
					Debug.error("Error on line #{lineno} in #{filename}")
				end
      end
    end
  end

	def load_module(module_file)
		begin
			require module_file
		rescue LoadError
			puts "Could not load module #{module_file}. I need a working module, sorry.\n"
			exit(1);
		end
 
		Debug.print("Loaded #{module_file}",2);
		@vars['module']=module_file

		@vars['module_ref'] = SqueezaPlugin.module.new(self)
		@vars['module_name']= SqueezaPlugin.module_name

		if (@vars['module_name'] == nil)
			puts "Module does not appear to be a Squeeza module."
			exit(1)
		end

		Debug.print("Module #{@vars['module_name']} has announced itself. Welcome.",2)

		@vars['module_ref'] 
	end

	def set_command(cmd, &block)
		Debug.print("Saving block for command #{cmd}",2)
		if !@cmds[cmd].nil?	
			Debug.error("Duplicate command #{cmd} given by module #{@vars['module_name']}... ignoring.")
			return nil
		end

		@cmds[cmd] = {"block" => block}

		return block
	end

	def get_command(cmd)
		Debug.print("Checking command #{cmd}, it #{@cmds[cmd]?"exists":"does not exist"}.",2)
		return @cmds[cmd]['block'] if @cmds[cmd]
		return nil
	end
	
	def initialize

		@vars = {}
		@cmds = {}

		opts = GetoptLong.new(
		  [ "--config",      "-c", GetoptLong::REQUIRED_ARGUMENT ],
		  [ "--debug",       "-v", GetoptLong::REQUIRED_ARGUMENT ],
		  [ "--help",        "-h", GetoptLong::NO_ARGUMENT ],
		  [ "--module",      "-m", GetoptLong::REQUIRED_ARGUMENT ]
		)
		opts.quiet = true

		config_loaded=false

		begin
			opts.each do |opt, arg|
				case opt
				when "--config"
					read_config(arg.chomp)
					config_loaded=true
				when "--debug"
					Debug.set_level(arg.chomp.to_i)
				when "--help"
					usage
					exit(0)
				when "--module"
					#load the module. without a module, this is just a shell :)
					@vars['module']= arg.chomp
				end
			end

			rescue GetoptLong::InvalidOption => e
				Debug.error(e.to_s)
				exit(1)
		end

		#attempt to read default config file
		read_config("squeeza.config") if !config_loaded

		if (!@vars.has_key?('module'))
			puts "No module specified: use either CLI argument (--module) or config file line (module=)";
			exit(1);
		end
		
		load_module(@vars['module'])
		
	end

	def interpret_set(kv)
		if kv.nil?
			getvars.sort.each{|k,v| puts "#{k} = #{v}"}
		else
			k, v = kv.split(/=/,2)
			k.strip!
			if (v.nil?)
				puts "#{k} = #{getv(k)}"
			else
				v.strip!
				setv(k,v)

				#special case when module is reloaded from CLI
				if k == "module"
					load_module(k)
				end

				Debug.print("#{k} => #{getv(k)}",2)
			end
		end
		
	end

end


def print_logo
  logo = []
  logo << " ___  __ _ _   _  ___  ___ ______ _ "
  logo << "/ __|/ _` | | | |/ _ \\/ _ \\_  / _` |"
  logo << "\\__ \\ (_| | |_| |  __/  __// / (_| |"
  logo << "|___/\\__, |\\__,_|\\___|\\___/___\\__,_|"
  logo << "        | |"
  logo << "        |_|"
  logo.each{|x| print x+"\n"}
end

#def underline
#  print_logo
#  print "\n"
#  1.upto(36){|step|
#    print "#{27.chr}[1A#{27.chr}[0G#{27.chr}[K"
#    print " " * step
#    print "=\n"
#    sleep 0.01
#  }
#  36.downto(1){|step|
#    print "#{27.chr}[1A#{27.chr}[0G#{27.chr}[K"
#    print " " * step
#    print "=\n"
#    sleep 0.01
#  }
#  print "#{27.chr}[1A#{27.chr}[0G#{27.chr}[K"
#end

begin
	print_logo
	puts "\nSqueeza tha cheeza v#{version}"
	puts "(c) {marco|haroon}@sensepost.com 2008\n\n"

	config = SqueezaConfig.new
	
	case config.getv("shell")
	when "cli"
		sh = SqueezaShell.new(config)
	when "passthru"
		sh = PassthruShell.new(config)
	else 
		Debug.error("No such shell #{config.getv("shell")}. exiting")
		exit(1)
	end

	sh.run
end
