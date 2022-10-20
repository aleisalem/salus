require 'json'
require 'salus/scanners/base'

# Gitleaks is a SAST tool for detecting and preventing hardcoded secrets 
# like passwords, api keys, and tokens in git repos. Gitleaks is an easy-to-use, 
# all-in-one solution for detecting secrets, past or present, in your code.
# https://github.com/zricethezav/gitleaks

module Salus::Scanners
  class Gitleaks < Base
    include Salus::Formatting

    GITLEAKS_COMMAND = "gitleaks detect --report-format json --report-path /dev/stdout --no-banner ".freeze

    def should_run?
      @repository.all_files_present?
    end

    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def run
      # Declare base command
      options = get_config_options # Used for options that have values (i.e., not flags)
      command = GITLEAKS_COMMAND  
      command += "--redact " if @config["redact"] == true
      command += "--no-git" if @config["no-git"] == true
      command += "#{options}"
      shell_return = run_shell(command, chdir: @repository.path_to_repo)

      # Gitleaks has the following behavior:
      #   - no leaks present            - exit 0 and log to STDOUT
      #   - leaks or error encounterd   - exit --exit-code defined in salus-default.yaml and log to STDOUT
      #   - unknown flag                - exit 126 and log to STDERR
      return report_success if shell_return.success? 

      # report_failure 

      if @config.has_key? "exit-code"
        if shell_return.status.to_s == @config["exit-code"]
          log(shell_return.stdout)
          secrets = JSON.parse(shell_return.stdout)
          if !secrets.empty? && @config['verbose']
            report_stdout(shell_return.stdout) # Write the raw STDOUT to report
            #log(secrets)
            return report_failure
          end
        else
          report_error(
            "Gitleaks exited with an unexpected exit status, #{shell_return.stderr}",
            status: shell_return.status
          )
          report_stderr(shell_return.stderr)
        end
      end
    end

    def get_config_options
      build_options(
        prefix: '--',
        suffix: ' ',
        separator: ' ',
        args: {
          'exit-code': {
            type: :string,
            regex: /^\d+$/
          }
        }
      ) 
    end

    def version
      shell_return = run_shell('gitleaks version')
      shell_return.stdout&.strip.sub('v', '')
    end

    def self.supported_languages
      ['all']
    end

  end
end