module Sarif
  class NodejsscanSarif < BaseSarif
    include Salus::SalusBugsnag

    NODEJSSCAN_URI = 'https://github.com/ajinabraham/nodejsscan'.freeze

    def initialize(scan_report, repo_path = nil)
      super(scan_report, {}, repo_path)
      @uri = NODEJSSCAN_URI
      @logs = parse_scan_report!(scan_report)
    end

    def parse_scan_report!(scan_report)
      logs = @scan_report.log('')
      return [] if logs.strip.empty?

      raw_report = JSON.parse(logs)
      all_issues = []
      if raw_report.has_key? "nodejs"
        all_rules = raw_report["nodejs"]
      end
      all_rules.each do |ruleId, ruleDetails|
        if ruleDetails.has_key? "files"
          ruleDetails["files"].each do |issue|
            issue["rule"] = {}
            issue["rule"]["id"] = ruleId
            issue["rule"]["metadata"] = ruleDetails["metadata"]         
            all_issues.push(issue)
          end
        end
       end
      all_issues
    rescue JSON::ParserError => e
      bugsnag_notify(e.message)
      []
    rescue => e
      []
    end

    def parse_issue(issue)
      parsed_issue = {
          # Keys needed for "results"
          id: issue["rule"]["id"],
          level: "MEDIUM",
          details: issue["rule"]["metadata"]["description"],
          uri: issue["file_path"],
          code: issue["match_string"],
          start_line: issue["match_lines"][0],
          start_column: issue["match_position"][0],
          properties: {
            cwe: issue["rule"]["metadata"]["cwe"],
            owasp: issue["rule"]["metadata"]["owasp-web"]
          },
          # Keys needed for "rules"
          name: "%s - %s" % [issue["rule"]["metadata"]["owasp-web"], issue["rule"]["metadata"]["description"]],
          help_url: "mailto:security@gridx.de",
          # Keys needed for runs object
          suppressed: false       
      }
    rescue => e
      bugsnag_notify(e.message)
      {}
      parsed_issue
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
