include("compat.inc");

if(description) {
 script_id(200010);
 script_version ("$Revision: 0.2 $");
 script_name(english: "Port Scan Plugin");
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

open_ports = "The following port was found open: ";
for (i=1;i<=1023;i++) {
 sock = open_sock_tcp(i);
 if (sock) {
  open_port = open_ports + i + ".";
  security_hole(port: i, extra: open_port);
 }
}

 exit(0);
