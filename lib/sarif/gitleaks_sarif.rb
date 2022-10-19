module Sarif
  class GitleaksSarif < BaseSarif
    include Salus::SalusBugsnag

    GITLEAKS_URI = 'https://github.com/zricethezav/gitleaks'.freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = GITLEAKS_URI
      @logs = parse_scan_report!(scan_report)
    end

    def parse_scan_report!(scan_report)
      logs = @scan_report.log('')
      return [] if logs.strip.empty?

      all_secrets = JSON.parse(logs)
      all_secrets
      # parsed_secrets = []
      # all_secrets.each do |secret|
      #   parsed_secrets.push(parse_issue(secret))
      # end      

    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      []
    rescue => e
      []
    end

    def parse_issue(secret)
      commit_data = "%s: %s by %s on %s" % [secret["Commit"], secret["Message"], secret["Email"], secret["Date"]]
      lines = "%s-%s" % [secret["StartLine"], secret["EndLine"]]
      columns = "%s-%s" % [secret["StartColumn"], secret["EndColumn"]]
      parsed_secret = {
          # Keys needed for "results"
          id: secret["RuleID"],
          level: "error",
          details: "%s found in commit %s." % [secret["Description"], secret["Commit"]],
          uri: secret["File"],
          code: secret["Secret"],
          start_line: secret["StartLine"],
          start_column: secret["StartColumn"],
          properties: {
            tags: secret["Tags"],
            entropy: secret["Entropy"],
            commit: secret["Commit"],
            author: secret["Author"],
            email: secret["Email"]
          },
          # Keys needed for "rules"
          name: secret["Description"],
          help_url: "mailto:security@gridx.de",
          # Keys needed for runs object
          suppressed: false
          
      }
    rescue => e
      bugsnag_notify(e.message)
      {}

      parsed_secret
    end
  
    def self.snippet_possibly_in_git_diff?(snippet, lines_added)
      # Bandit snippet looks like
      #   "2 \n3 self.process = subprocess.Popen('/bin/echo', shell=True)\n4 foo()\n"
      lines = snippet.split("\n")
      # using any? because snippet may include surrounding code that may not be in git diff
      lines.any? do |line|
        line = line.split(' ', 2)[1]
        if line.nil?
          # maybe the line of code has some special pattern
          # we'll just not deal with it and assume snippet may be in git diff
          true
        else
          lines_added.keys.include?(line) && !line.strip.empty?
        end
      end
    end

  end
end
