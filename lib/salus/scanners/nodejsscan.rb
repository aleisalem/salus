require 'json'
require 'salus/scanners/base'

# Nodejsscan is a static security code scanner (SAST) for Node.js applications 
# powered by libsast and semgrep.
# https://github.com/ajinabraham/nodejsscan

module Salus::Scanners
  class Nodejsscan < Base
    include Salus::Formatting

    NODEJSSCAN_COMMAND = "njsscan --json ".freeze

    def should_run?
      @repository.js_files_present? || @repository.ts_files_present?
    end

    def self.scanner_type
      Salus::ScannerTypes::SAST
    end

    def run
      # Declare base command
      command = NODEJSSCAN_COMMAND  
      command += "--missing-controls " if @config["missing-controls"] == true
      command += "." # Scan the current directory
      shell_return = run_shell(command, chdir: @repository.path_to_repo)

      # Nodejsscan has the following behavior:
      #   - No issues found (only warnings)    - exit 0 and log to STDOUT
      #   - Issues found                       - exit 1 and log to STDOUT
      #   - Other errors                       - exit 2 and log to STDOUT
      return report_success if shell_return.success? 

      if shell_return.status == 1
          log(shell_return.stdout)
          issues = JSON.parse(shell_return.stdout)
          report_stdout(shell_return.stdout) # Write the raw STDOUT to report
          return report_failure
      else
          report_error(
            "Nodejsscan exited with an unexpected exit status, #{shell_return.stderr}",
            status: shell_return.status
          )
          report_stderr(shell_return.stderr)
      end
    end

    def get_config_options
      build_options(
        prefix: '--',
        suffix: ' ',
        separator: ' ',
        args: {
          'exit-warning': {
            type: :string,
            regex: /^\d+$/
          }
        }
      ) 
    end

    def version
      shell_return = run_shell('njsscan --version')
      shell_return.stderr&.split(' ')&.dig(2)&.sub('v', '')
    end

    def self.supported_languages
      ['javascript', 'typescript']
    end

  end
end